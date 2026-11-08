package liveness

import "testing"

func FuzzDecodeFixedProbe(f *testing.F) {
	f.Add(make([]byte, headerSize))
	f.Add([]byte("V6LP"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decode(data)
	})
}
