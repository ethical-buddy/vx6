package record

import (
	"fmt"
	"strings"
)

const (
	MinNodeNameLength = 3
	MaxNodeNameLength = 16
)

func NormalizeNodeName(name string) (string, error) {
	canonical := strings.ToUpper(name)
	if err := validateCanonicalNodeName(canonical); err != nil {
		return "", err
	}
	return canonical, nil
}

func ValidateNodeName(name string) error {
	_, err := NormalizeNodeName(name)
	return err
}

func ValidateCanonicalNodeName(name string) error {
	if name != strings.ToUpper(name) {
		return fmt.Errorf("node name %q must be uppercase", name)
	}
	return validateCanonicalNodeName(name)
}

func validateCanonicalNodeName(name string) error {
	if len(name) < MinNodeNameLength {
		return fmt.Errorf("node name must contain at least %d characters", MinNodeNameLength)
	}
	if len(name) > MaxNodeNameLength {
		return fmt.Errorf("node name %q exceeds %d characters", name, MaxNodeNameLength)
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return fmt.Errorf("node name %q cannot start or end with a hyphen", name)
	}
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return fmt.Errorf("node name %q contains unsupported characters; use uppercase letters, digits, or hyphens", name)
		}
	}
	return nil
}
