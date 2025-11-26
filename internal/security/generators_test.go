package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateShortCode_Returns6Characters(t *testing.T) {
	code := generateShortCode()

	assert.Len(t, code, 6, "should return 6-character code")
}

func TestGenerateShortCode_ContainsOnlyValidHexCharacters(t *testing.T) {
	code := generateShortCode()

	validChars := "0123456789ABCDEF"
	for _, char := range code {
		assert.Contains(t, validChars, string(char), "should only contain valid hex characters (0-9, A-F)")
	}
}

func TestGenerateShortCode_IsUppercase(t *testing.T) {
	code := generateShortCode()

	for _, char := range code {
		if char >= 'A' && char <= 'F' {
			assert.True(t, char >= 'A' && char <= 'F', "letters should be uppercase")
		}
	}
	assert.NotContains(t, code, "a", "should not contain lowercase a")
	assert.NotContains(t, code, "b", "should not contain lowercase b")
	assert.NotContains(t, code, "c", "should not contain lowercase c")
	assert.NotContains(t, code, "d", "should not contain lowercase d")
	assert.NotContains(t, code, "e", "should not contain lowercase e")
	assert.NotContains(t, code, "f", "should not contain lowercase f")
}

func TestGenerateShortCode_GeneratesDifferentCodes(t *testing.T) {
	codes := make(map[string]bool)

	for i := 0; i < 100; i++ {
		code := generateShortCode()
		codes[code] = true
	}

	assert.Greater(t, len(codes), 95, "should generate different codes (at least 95% unique in 100 attempts)")
}

func TestGenerateShortCode_NoInvalidCharacters(t *testing.T) {
	invalidChars := []string{"G", "H", "J", "Z", "g", "h", "j", "z", "!", "@", " "}

	for i := 0; i < 20; i++ {
		code := generateShortCode()
		for _, invalid := range invalidChars {
			assert.NotContains(t, code, invalid, "should not contain invalid character: %s", invalid)
		}
	}
}
