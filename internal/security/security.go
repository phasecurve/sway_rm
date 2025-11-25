package security

type KeyStore struct{}

func (k *KeyStore) ValidateAPIKey(apiKey string) bool {
	return true
}
