package proto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestReadLengthPrefixedRejectsOversizeBeforeReadingPayload(t *testing.T) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 1025)
	if _, err := ReadLengthPrefixed(bytes.NewReader(header[:]), 1024); err == nil {
		t.Fatal("accepted a length-prefixed payload above the configured cap")
	}
}

func TestReadHeaderRejectsUnknownKind(t *testing.T) {
	_, err := ReadHeader(bytes.NewReader([]byte{'V', 'X', '6', '1', 255}))
	if err == nil {
		t.Fatal("accepted unknown VX6 message kind")
	}
}

func TestWriteLengthPrefixedRejectsEmptyFrame(t *testing.T) {
	if err := WriteLengthPrefixed(&bytes.Buffer{}, nil); err == nil {
		t.Fatal("wrote empty frame")
	}
}

func FuzzReadLengthPrefixedIsBounded(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 'x'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadLengthPrefixed(bytes.NewReader(data), 4096)
	})
}
