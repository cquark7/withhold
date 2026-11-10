package detector

import (
	"errors"
	"strings"
)

// ParseConfidence mirrors Betterleaks' CLI normalization without echoing input.
// Detection and ranking remain upstream's responsibility. Empty disables the
// minimum, preserving the default inclusion of every confidence level.
func ParseConfidence(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "low", "medium", "high":
		return value, nil
	default:
		return "", errors.New("confidence must be low, medium, high, or empty for no minimum")
	}
}
