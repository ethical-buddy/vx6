package strictjson

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecodeRejectsDuplicateUnknownAndTrailingFields(t *testing.T) {
	type message struct {
		Action string `json:"action"`
	}
	for _, input := range []string{
		`{"action":"lookup","action":"store"}`,
		`{"action":"lookup","extra":true}`,
		`{"action":"lookup"} {}`,
	} {
		var got message
		if err := Decode([]byte(input), &got); err == nil {
			t.Fatalf("accepted invalid JSON %s", input)
		}
	}
}

func TestDecodeEnforcesNestingAndDocumentBudgets(t *testing.T) {
	var got any
	deep := strings.Repeat("[", maxDepth+1) + "0" + strings.Repeat("]", maxDepth+1)
	if err := Decode([]byte(deep), &got); err == nil {
		t.Fatal("accepted over-deep JSON")
	}
	if err := Decode([]byte(strings.Repeat(" ", maxDocumentBytes+1)+"0"), &got); err == nil {
		t.Fatal("accepted over-size JSON")
	}
	fields := make([]string, maxObjectFields+1)
	for i := range fields {
		fields[i] = fmt.Sprintf(`"k%d":0`, i)
	}
	if err := Decode([]byte("{"+strings.Join(fields, ",")+"}"), &got); err == nil {
		t.Fatal("accepted too many JSON fields")
	}
}

func FuzzDecodeNeverPanics(f *testing.F) {
	f.Add([]byte(`{"action":"lookup"}`))
	f.Add([]byte(`{"action":"lookup","action":"store"}`))
	f.Add([]byte("["))
	f.Fuzz(func(t *testing.T, data []byte) {
		var dst map[string]any
		_ = Decode(data, &dst)
	})
}
