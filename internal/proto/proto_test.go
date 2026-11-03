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
