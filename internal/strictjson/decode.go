package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

const (
	maxDocumentBytes = 1 << 20
	maxDepth         = 64
	maxObjectFields  = 4096
	maxArrayElements = 4096
	maxTokens        = 32768
)

// Decode accepts exactly one JSON value, rejects duplicate object keys and
// unknown struct fields, and leaves no trailing data unread.
func Decode(data []byte, dst any) error {
	if len(data) == 0 || len(data) > maxDocumentBytes {
		return fmt.Errorf("JSON document size %d is outside the allowed range", len(data))
	}
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
	budget := scanBudget{}
	if err := scanValue(decoder, first, 0, &budget); err != nil {
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

type scanBudget struct {
	fields int
	items  int
	tokens int
}

func scanValue(decoder *json.Decoder, token json.Token, depth int, budget *scanBudget) error {
	budget.tokens++
	if budget.tokens > maxTokens {
		return fmt.Errorf("JSON token budget exceeded")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxDepth)
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			budget.fields++
			if budget.fields > maxObjectFields {
				return fmt.Errorf("JSON object field budget exceeded")
			}
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
			if err := scanValue(decoder, value, depth+1, budget); err != nil {
				return err
			}
		}
		close, err := decoder.Token()
		if err != nil || close != json.Delim('}') {
			return fmt.Errorf("invalid JSON object termination")
		}
	case '[':
		for decoder.More() {
			budget.items++
			if budget.items > maxArrayElements {
				return fmt.Errorf("JSON array element budget exceeded")
			}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanValue(decoder, value, depth+1, budget); err != nil {
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
