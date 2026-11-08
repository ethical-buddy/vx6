package onion

import (
	"bytes"
	"testing"
)

func TestCellRoundTrip(t *testing.T) {
	t.Parallel()

	cid := circuitIDFromString("demo-circuit")
	original := cell{
		Type:      cellTypeRelay,
		CircuitID: cid,
		Payload:   []byte("payload"),
	}

	var buf bytes.Buffer
	if err := writeCell(&buf, original); err != nil {
		t.Fatalf("write cell: %v", err)
	}
	got, err := readCell(&buf)
	if err != nil {
		t.Fatalf("read cell: %v", err)
	}
	if got.Type != original.Type || got.CircuitID != original.CircuitID || string(got.Payload) != string(original.Payload) {
		t.Fatalf("unexpected cell roundtrip: %+v", got)
	}
}

func FuzzDecodeRelayEnvelope(f *testing.F) {
	f.Add([]byte("vx6r\x01\x00"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = decodeRelayEnvelope(data)
	})
}

func TestRelayEnvelopeRoundTrip(t *testing.T) {
	t.Parallel()

	payload, err := encodeRelayEnvelope(relayCmdBegin, []byte("hello"))
	if err != nil {
		t.Fatalf("encode relay envelope: %v", err)
	}
	cmd, body, recognized, err := decodeRelayEnvelope(payload)
	if err != nil {
		t.Fatalf("decode relay envelope: %v", err)
	}
	if !recognized || cmd != relayCmdBegin || string(body) != "hello" {
		t.Fatalf("unexpected relay envelope decode: cmd=%d body=%q recognized=%v", cmd, string(body), recognized)
	}
}

func TestLayeredRelayWrapUnwrap(t *testing.T) {
	t.Parallel()

	cid := circuitIDFromString("layered-circuit")
	keyAClient, err := deriveCircuitKeys([]byte("shared-secret-a"), cid)
	if err != nil {
		t.Fatalf("derive key A: %v", err)
	}
	keyARelay, err := deriveCircuitKeys([]byte("shared-secret-a"), cid)
	if err != nil {
		t.Fatalf("derive relay key A: %v", err)
	}
	keyBClient, err := deriveCircuitKeys([]byte("shared-secret-b"), cid)
	if err != nil {
		t.Fatalf("derive key B: %v", err)
	}
	keyBRelay, err := deriveCircuitKeys([]byte("shared-secret-b"), cid)
	if err != nil {
		t.Fatalf("derive relay key B: %v", err)
	}
	keyCClient, err := deriveCircuitKeys([]byte("shared-secret-c"), cid)
	if err != nil {
		t.Fatalf("derive key C: %v", err)
	}
	keyCRelay, err := deriveCircuitKeys([]byte("shared-secret-c"), cid)
	if err != nil {
		t.Fatalf("derive relay key C: %v", err)
	}

	plain, err := encodeRelayEnvelope(relayCmdData, []byte("hello layered relay"))
	if err != nil {
		t.Fatalf("encode plain relay body: %v", err)
	}

	payload := plain
	payload = keyCClient.sealForward(payload)
	payload = keyBClient.sealForward(payload)
	payload = keyAClient.sealForward(payload)

	outer, err := keyARelay.openForward(payload)
	if err != nil {
		t.Fatalf("unwrap A: %v", err)
	}
	if _, _, recognized, err := decodeRelayEnvelope(outer); err != nil || recognized {
		t.Fatalf("expected hop A to see opaque payload, recognized=%v err=%v", recognized, err)
	}
	middle, err := keyBRelay.openForward(outer)
	if err != nil {
		t.Fatalf("unwrap B: %v", err)
	}
	if _, _, recognized, err := decodeRelayEnvelope(middle); err != nil || recognized {
		t.Fatalf("expected hop B to see opaque payload, recognized=%v err=%v", recognized, err)
	}
	inner, err := keyCRelay.openForward(middle)
	if err != nil {
		t.Fatalf("unwrap C: %v", err)
	}
	cmd, body, recognized, err := decodeRelayEnvelope(inner)
	if err != nil {
		t.Fatalf("decode final relay body: %v", err)
	}
	if !recognized || cmd != relayCmdData || string(body) != "hello layered relay" {
		t.Fatalf("unexpected final relay body: cmd=%d body=%q", cmd, string(body))
	}

	response, err := encodeRelayEnvelope(relayCmdConnected, nil)
	if err != nil {
		t.Fatalf("encode backward relay body: %v", err)
	}
	response = keyCRelay.sealBackward(response)
	response = keyBRelay.sealBackward(response)
	response = keyARelay.sealBackward(response)

	response, err = keyAClient.openBackward(response)
	if err != nil {
		t.Fatalf("open backward A: %v", err)
	}
	response, err = keyBClient.openBackward(response)
	if err != nil {
		t.Fatalf("open backward B: %v", err)
	}
	response, err = keyCClient.openBackward(response)
	if err != nil {
		t.Fatalf("open backward C: %v", err)
	}
	cmd, body, recognized, err = decodeRelayEnvelope(response)
	if err != nil {
		t.Fatalf("decode backward relay body: %v", err)
	}
	if !recognized || cmd != relayCmdConnected || len(body) != 0 {
		t.Fatalf("unexpected backward relay body: cmd=%d len=%d recognized=%v", cmd, len(body), recognized)
	}
}
