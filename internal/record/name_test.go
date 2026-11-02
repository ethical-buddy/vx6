package record

import "testing"

func TestValidateNodeName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "valid simple", value: "ALPHA"},
		{name: "valid hyphen", value: "ALPHA-01"},
		{name: "minimum length", value: "A1B"},
		{name: "maximum length", value: "ABCDEFGHIJKLMNOP"},
		{name: "empty rejected", value: "", wantErr: true},
		{name: "too short rejected", value: "AB", wantErr: true},
		{name: "too long rejected", value: "ABCDEFGHIJKLMNOPQ", wantErr: true},
		{name: "leading hyphen rejected", value: "-ALPHA", wantErr: true},
		{name: "trailing hyphen rejected", value: "ALPHA-", wantErr: true},
		{name: "underscore rejected", value: "ALPHA_BETA", wantErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateNodeName(tc.value)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestNormalizeNodeNameUppercasesUserInput(t *testing.T) {
	got, err := NormalizeNodeName("alpha-42")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ALPHA-42" {
		t.Fatalf("normalized name = %q, want ALPHA-42", got)
	}
}

func TestValidateCanonicalNodeNameRejectsLowercaseWireValue(t *testing.T) {
	if err := ValidateCanonicalNodeName("alpha"); err == nil {
		t.Fatal("accepted non-canonical lowercase wire name")
	}
}
