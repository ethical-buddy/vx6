package serviceproxy

import (
	"testing"

	"github.com/vx6/vx6/internal/strictjson"
)

func FuzzServiceOpenRequestSchema(f *testing.F) {
	f.Add([]byte(`{"version":1,"action":"open","service_name":"web"}`))
	f.Add([]byte(`{"version":1,"action":"exec","service_name":"web"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var request ConnectRequest
		if strictjson.Decode(data, &request) == nil {
			_ = request.Validate()
		}
	})
}
