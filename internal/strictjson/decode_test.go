package strictjson

import "testing"

func TestDecodeAcceptsExactObject(t *testing.T) {
	var value struct {
		Name string `json:"name"`
	}
	if err := Decode([]byte(`{"name":"ALPHA"}`), &value); err != nil {
		t.Fatal(err)
	}
	if value.Name != "ALPHA" {
		t.Fatalf("decoded name = %q", value.Name)
	}
}

func TestDecodeRejectsUnknownDuplicateAndTrailingFields(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "unknown field", raw: `{"name":"ALPHA","extra":true}`},
		{name: "duplicate field", raw: `{"name":"ALPHA","name":"BETA"}`},
		{name: "nested duplicate", raw: `{"name":"ALPHA","nested":{"x":1,"x":2}}`},
		{name: "trailing object", raw: `{"name":"ALPHA"} {}`},
		{name: "trailing text", raw: `{"name":"ALPHA"} trailing`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var value struct {
				Name string `json:"name"`
			}
			if err := Decode([]byte(test.raw), &value); err == nil {
				t.Fatal("accepted non-canonical JSON")
			}
		})
	}
}
