package secure

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/vx6/vx6/internal/proto"
)

func FuzzReadHandshakeIsBounded(f *testing.F) {
	f.Add([]byte(`{"version":2,"node_id":"vx6_"}`))
	f.Add([]byte(`{"version":2,"node_id":"x","public_key":"x","ephemeral":"x","signature":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > maxHandshakeSize {
			return
		}
		frame := make([]byte, 4+len(data))
		binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
		copy(frame[4:], data)
		_, _ = readHello(bytes.NewReader(frame), proto.KindServiceConn)
	})
}
