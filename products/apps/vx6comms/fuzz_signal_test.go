package main

import (
	"encoding/json"
	"testing"
)

func FuzzRTCSignalJSON(f *testing.F) {
	f.Add([]byte(`{"version":1,"from_id":"a","to_id":"b","type":"offer","id":"x"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var sig rtcSignal
		_ = json.Unmarshal(data, &sig)
	})
}

