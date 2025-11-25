package security

import (
	"time"

	bolt "go.etcd.io/bbolt"
)

const apiKeysBucketName = "apiKeys"

type KeyStore struct {
	db *bolt.DB
}

func NewKeyStore(db *bolt.DB) *KeyStore {
	return &KeyStore{db: db}
}

func (k *KeyStore) ValidateAPIKey(apiKey string) bool {
	var isValid bool
	if err := k.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(apiKeysBucketName))
		if b == nil {
			return nil
		}
		expiryBytes := b.Get([]byte(apiKey))
		if expiryBytes == nil {
			return nil
		}

		var expiresAt time.Time
		if err := expiresAt.UnmarshalBinary(expiryBytes); err != nil {
			return err
		}

		isValid = time.Now().Before(expiresAt)
		return nil
	}); err != nil {
		return false
	}

	return isValid
}

func (k *KeyStore) StoreAPIKey(apiKey string, expiresAt time.Time) error {
	return k.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(apiKeysBucketName))
		if err != nil {
			return err
		}
		expiresAtBin, err := expiresAt.MarshalBinary()
		if err != nil {
			return err
		}
		return b.Put([]byte(apiKey), expiresAtBin)
	})
}
