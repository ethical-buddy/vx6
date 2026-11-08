package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Decode accepts exactly one JSON value, rejects duplicate object keys and
// unknown struct fields, and leaves no trailing data unread.
func Decode(data []byte, dst any) error {
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := scanValue(decoder, first); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func scanValue(decoder *json.Decoder, token json.Token) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanValue(decoder, value); err != nil {
				return err
			}
		}
		close, err := decoder.Token()
		if err != nil || close != json.Delim('}') {
			return fmt.Errorf("invalid JSON object termination")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanValue(decoder, value); err != nil {
				return err
			}
		}
		close, err := decoder.Token()
		if err != nil || close != json.Delim(']') {
			return fmt.Errorf("invalid JSON array termination")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}
