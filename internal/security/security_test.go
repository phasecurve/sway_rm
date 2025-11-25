package security

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	bolt "go.etcd.io/bbolt"
)

func TestValidateAPIKey_ValidKey_ReturnsTrue(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "apiKeys.db")
	db, err := bolt.Open(dbPath, 0600, nil)
	assert.NoError(t, err)
	defer db.Close()

	keyStore := NewKeyStore(db)

	apiKey := "test-api-key-123"
	expiresAt := time.Now().Add(1 * time.Hour)
	err = keyStore.StoreAPIKey(apiKey, expiresAt)
	assert.NoError(t, err)

	valid := keyStore.ValidateAPIKey(apiKey)

	assert.True(t, valid, "valid API key should return true")
}

func TestValidateAPIKey_NonExistentKey_ReturnsFalse(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	db, err := bolt.Open(dbPath, 0600, nil)
	assert.NoError(t, err)
	defer db.Close()

	keyStore := NewKeyStore(db)

	valid := keyStore.ValidateAPIKey("non-existent-key")

	assert.False(t, valid, "non-existent API key should return false")
}
