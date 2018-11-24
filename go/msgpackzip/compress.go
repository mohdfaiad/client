package msgpackzip

import (
	"bytes"
	"fmt"
	"sort"
)

type compressor struct {
	input          []byte
	valueWhiteList valueWhiteList
	collectMapKeys bool
}

func newCompressor(b []byte, wl valueWhiteList, c bool) *compressor {
	return &compressor{input: b, valueWhiteList: wl, collectMapKeys: c}
}

type ValueWhitelist struct {
	Strings  []string
	Binaries [][]byte
}

type valueWhiteList struct {
	strings     map[string]bool
	binaries    map[string]bool
	allValuesOk bool
}

func (v ValueWhitelist) mapify() valueWhiteList {
	ret := emptyWhiteList()
	for _, s := range v.Strings {
		ret.strings[s] = true
	}
	for _, b := range v.Binaries {
		ret.strings[string(b)] = true
	}
	return ret
}

func (v *valueWhiteList) hasString(s string) bool {
	if v.allValuesOk {
		return true
	}
	return v.strings[s]
}

func (v *valueWhiteList) hasBinary(b []byte) bool {
	if v.allValuesOk {
		return true
	}
	return v.binaries[string(b)]
}

func emptyWhiteList() valueWhiteList {
	return valueWhiteList{
		strings:  make(map[string]bool),
		binaries: make(map[string]bool),
	}
}

func (v valueWhiteList) withAllValuesOk() valueWhiteList {
	v.allValuesOk = true
	return v
}

func CompressWithWhiteList(input []byte, wl ValueWhitelist) (output []byte, err error) {
	return newCompressor(input, wl.mapify(), true).run()
}

func Compress(input []byte) (output []byte, err error) {
	return newCompressor(input, emptyWhiteList(), true).run()
}

func ReportValuesFrequencies(input []byte) (ret []Frequency, err error) {
	return newCompressor(input, emptyWhiteList().withAllValuesOk(), false).collectAndSortFrequencies()
}

func (c *compressor) collectAndSortFrequencies() (ret []Frequency, err error) {

	freqs, err := c.collectFrequencies()
	if err != nil {
		return nil, err
	}
	freqsSorted, err := c.sortFrequencies(freqs)
	if err != nil {
		return nil, err
	}
	return freqsSorted, nil
}

func (c *compressor) run() (output []byte, err error) {

	freqsSorted, err := c.collectAndSortFrequencies()
	if err != nil {
		return nil, err
	}
	keys, err := c.frequenciesToMap(freqsSorted)
	if err != nil {
		return nil, err
	}
	output, err = c.output(keys)
	return output, err
}

type binaryMapKey string

func (c *compressor) collectFrequencies() (ret map[interface{}]int, err error) {

	ret = make(map[interface{}]int)
	mapKeyHook := func(d decodeStack) (decodeStack, error) {
		d.hooks = msgpackDecoderHooks{
			stringHook: func(l msgpackInt, s string) error {
				ret[s]++
				return nil
			},
			intHook: func(l msgpackInt) error {
				i, err := l.toInt64()
				if err != nil {
					return err
				}
				ret[i]++
				return nil
			},
			fallthroughHook: func(i interface{}, s string) error {
				return fmt.Errorf("bad map key (type %T)", i)
			},
		}
		return d, nil
	}
	hooks := msgpackDecoderHooks{
		stringHook: func(l msgpackInt, s string) error {
			if c.valueWhiteList.hasString(s) {
				ret[s]++
			}
			return nil
		},
		binaryHook: func(l msgpackInt, b []byte) error {
			s := string(b)
			if c.valueWhiteList.hasBinary(b) {
				ret[binaryMapKey(s)]++
			}
			return nil
		},
	}
	if c.collectMapKeys {
		hooks.mapKeyHook = mapKeyHook
	}
	err = newMsgpackDecoder(bytes.NewReader(c.input)).run(hooks)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

type Frequency struct {
	Key  interface{}
	Freq int
}

func (c *compressor) sortFrequencies(freqs map[interface{}]int) (ret []Frequency, err error) {

	ret = make([]Frequency, len(freqs))
	var i int
	for k, v := range freqs {
		ret[i] = Frequency{k, v}
		i++
	}
	sort.SliceStable(ret, func(i, j int) bool { return ret[i].Freq > ret[j].Freq })
	return ret, nil
}

func (c *compressor) frequenciesToMap(freqs []Frequency) (keys map[interface{}]uint, err error) {
	ret := make(map[interface{}]uint, len(freqs))
	for i, freq := range freqs {
		ret[freq.Key] = uint(i)
	}
	return ret, nil
}

func (c *compressor) output(keys map[interface{}]uint) (output []byte, err error) {

	version := 1
	data, err := c.outputData(keys)
	if err != nil {
		return nil, err
	}
	compressedKeymap, err := c.outputCompressedKeymap(keys)
	if err != nil {
		return nil, err
	}
	return c.outputFinalProduct(version, data, compressedKeymap)
}

func (c *compressor) outputData(keys map[interface{}]uint) (output []byte, err error) {

	var data outputter

	hooks := data.decoderHooks()
	hooks.mapKeyHook = func(d decodeStack) (decodeStack, error) {
		d.hooks = msgpackDecoderHooks{
			intHook: func(l msgpackInt) error {
				i, err := l.toInt64()
				if err != nil {
					return err
				}
				val, ok := keys[i]
				if !ok {
					return fmt.Errorf("unexpected map key: %v", i)
				}
				return data.outputRawUint(val)
			},
			stringHook: func(l msgpackInt, s string) error {
				val, ok := keys[s]
				if !ok {
					return fmt.Errorf("unexpected map key: %q", s)
				}
				return data.outputRawUint(val)
			},
			fallthroughHook: func(i interface{}, s string) error {
				return fmt.Errorf("bad map key (type %T)", i)
			},
		}
		return d, nil
	}
	hooks.stringHook = func(l msgpackInt, s string) error {
		val, ok := keys[s]
		if ok {
			return data.outputExtUint(val)
		}
		return data.outputString(l, s)
	}
	hooks.binaryHook = func(l msgpackInt, b []byte) error {
		val, ok := keys[binaryMapKey(string(b))]
		if ok {
			return data.outputExtUint(val)
		}
		return data.outputBinary(l, b)
	}
	hooks.extHook = func(b []byte) error {
		return fmt.Errorf("cannot handle external data types")
	}

	err = newMsgpackDecoder(bytes.NewReader(c.input)).run(hooks)
	if err != nil {
		return nil, err
	}

	return data.Bytes(), nil
}

func (c *compressor) outputCompressedKeymap(keys map[interface{}]uint) (output []byte, err error) {

	var keymap outputter

	// Now write out a msgpack dictionary for the keymaps;
	// do it but hand, that's simplest for now, rather than pulling
	// in a new encoder.
	err = keymap.outputMapPrefix(msgpackIntFromUint(uint(len(keys))))
	if err != nil {
		return nil, err
	}
	for k, v := range keys {
		// Note that we reverse the map to make decoding easier
		err = keymap.outputInt(msgpackIntFromUint(v))
		if err != nil {
			return nil, err
		}
		err = keymap.outputStringOrUintOrBinary(k)
		if err != nil {
			return nil, err
		}
	}
	tmp := keymap.Bytes()

	compressedKeymap, err := gzipCompress(tmp)
	if err != nil {
		return nil, err
	}

	return compressedKeymap, nil
}

func (c *compressor) outputFinalProduct(version int, data []byte, compressedKeymap []byte) (output []byte, err error) {

	var ret outputter
	err = ret.outputArrayPrefix(msgpackIntFromUint(uint(3)))
	if err != nil {
		return nil, err
	}
	err = ret.outputInt(msgpackIntFromUint(uint(version)))
	if err != nil {
		return nil, err
	}
	err = ret.outputBinary(msgpackIntFromUint(uint(len(data))), data)
	if err != nil {
		return nil, err
	}
	err = ret.outputBinary(msgpackIntFromUint(uint(len(compressedKeymap))), compressedKeymap)
	if err != nil {
		return nil, err
	}

	return ret.Bytes(), nil
}
