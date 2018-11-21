package msgpackzip

import (
	"bytes"
	"errors"
	"fmt"
)

type inflator struct {
	input *bytes.Buffer
}

func newInflator(b []byte) *inflator {
	return &inflator{input: bytes.NewBuffer(b)}
}

func Inflate(input []byte) (output []byte, err error) {
	return newInflator(input).run()
}

func (c *inflator) run() (output []byte, err error) {

	version, compressedData, compressedKeymap, err := c.openOuter()
	if err != nil {
		return nil, err
	}
	if version != 1 {
		return nil, errors.New("can only support inflation of version 1")
	}

	keymap, err := c.inflateKeymap(compressedKeymap)
	if err != nil {
		return nil, err
	}

	ret, err := c.inflateData(keymap, compressedData)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

var ErrUnimplemented = errors.New("unimplemented")

func (c *inflator) openOuter() (version int, compressedData []byte, compressedKeymap []byte, err error) {

	idx := 0

	hooks := msgpackDecoderHooks{
		arrayStartHook: func(d decodeStack, mpi msgpackInt) (decodeStack, error) {
			if idx != 0 {
				return d, fmt.Errorf("should only have an array at the top level, but found one at index=%d", idx)
			}
			i, err := mpi.toLen()
			if err != nil {
				return d, err
			}
			if i != 3 {
				return d, fmt.Errorf("outside encoding should have 3 elements; got %d", i)
			}
			return d, nil
		},
		intHook: func(mpi msgpackInt) error {
			i, err := mpi.toLen()
			if err != nil {
				return err
			}
			if idx != 0 {
				return fmt.Errorf("need a version as first index (found at %d)", idx)
			}
			version = i
			idx++
			return nil
		},
		binaryHook: func(i msgpackInt, b []byte) error {
			switch idx {
			case 1:
				compressedData = b
			case 2:
				compressedKeymap = b
			default:
				return fmt.Errorf("got unexpected binary data at index=%d", idx)
			}
			idx++
			return nil
		},
		fallthroughHook: func(i interface{}, typ string) error {
			return fmt.Errorf("unexpected value of type %q at top level", typ)
		},
	}
	err = newMsgpackDecoder(c.input).run(hooks)
	if err != nil {
		return 0, nil, nil, err
	}
	return version, compressedData, compressedKeymap, nil
}

func (c *inflator) inflateKeymap(compressedKeymap []byte) (keymap map[uint]interface{}, err error) {
	rawKeymap, err := gzipInflate(compressedKeymap)
	if err != nil {
		return nil, err
	}

	var isValue bool
	var key uint

	putKey := func(k uint) error {
		if isValue {
			return errors.New("got a call to putKey when we expected a value")
		}
		val, dup := keymap[k]
		if dup {
			return fmt.Errorf("got a duplicated key in the keyMap: %d -> %v", k, val)
		}
		key = k
		isValue = true
		return nil
	}

	putValue := func(i interface{}) error {
		if !isValue {
			return errors.New("got a call to putValue when we expected a key")
		}
		keymap[key] = i
		isValue = false
		return nil
	}

	fallthroughHook := func(i interface{}, typ string) error {
		return fmt.Errorf("unexpected value of type %q in keymap", typ)
	}

	hooks := msgpackDecoderHooks{
		mapStartHook: func(d decodeStack, mpi msgpackInt) (decodeStack, error) {
			if keymap != nil {
				return d, fmt.Errorf("found a nested map in the keymap")
			}
			i, err := mpi.toLen()
			if err != nil {
				return d, err
			}
			keymap = make(map[uint]interface{}, i)
			return d, nil
		},
		mapKeyHook: func(d decodeStack) (decodeStack, error) {
			d.hooks = msgpackDecoderHooks{
				intHook: func(mpi msgpackInt) error {
					i, err := mpi.toLen()
					if err != nil {
						return err
					}
					return putKey(uint(i))
				},
				fallthroughHook: fallthroughHook,
			}
			return d, nil
		},
		mapValueHook: func(d decodeStack) (decodeStack, error) {
			d.hooks = msgpackDecoderHooks{
				intHook: func(mpi msgpackInt) error {
					i, err := mpi.toInt64()
					if err != nil {
						return err
					}
					return putValue(i)
				},
				stringHook: func(mpi msgpackInt, s string) error {
					return putValue(s)
				},
				fallthroughHook: fallthroughHook,
			}
			return d, nil
		},
		fallthroughHook: fallthroughHook,
	}
	buf := bytes.NewBuffer(rawKeymap)
	err = newMsgpackDecoder(buf).run(hooks)
	if err != nil {
		return nil, err
	}
	return keymap, nil
}

func (c *inflator) inflateData(keymap map[uint]interface{}, compressedData []byte) (ret []byte, err error) {
	var data outputter
	hooks := data.decoderHooks()
	hooks.mapKeyHook = func(d decodeStack) (decodeStack, error) {
		d.hooks = msgpackDecoderHooks{
			intHook: func(mpi msgpackInt) error {
				i, err := mpi.toLen()
				if err != nil {
					return err
				}
				key, ok := keymap[uint(i)]
				if !ok {
					return fmt.Errorf("Unknown map key: %d", i)
				}
				return data.outputStringOrUint(key)
			},
			fallthroughHook: func(i interface{}, typ string) error {
				return fmt.Errorf("Expected only int map keys; got a %q", typ)
			},
		}
		return d, nil
	}
	buf := bytes.NewBuffer(compressedData)
	err = newMsgpackDecoder(buf).run(hooks)
	if err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}
