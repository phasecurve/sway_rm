package api

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	bolt "go.etcd.io/bbolt"

	"github.com/phasecurve/sway_rm/internal/security"
)

func fakeShortCodeGenerator() func() string {
	return func() string { return "123456" }
}

func createTestKeyStore(t *testing.T) (*security.KeyStore, *bolt.DB) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
	})
	return security.NewKeyStore(db), db
}

func createTestLogger() *log.Logger {
	return log.New(os.Stderr, "", 0)
}

func TestStatus_NotPaired_Unauthorized(t *testing.T) {
	router := gin.Default()
	keyStore, _ := createTestKeyStore(t)
	server := &Server{
		KeyStore: keyStore,
		Logger:   createTestLogger(),
	}
	server.SetupRoutes(router)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/status", nil)
	router.ServeHTTP(w, req)

	actualStatusCode := w.Code

	assert.Equal(t, http.StatusUnauthorized, actualStatusCode, "unpaired request shows HTTP Unauthorized")
}

func TestRoot_ReturnsOK(t *testing.T) {
	router := gin.Default()

	keyStore, _ := createTestKeyStore(t)
	server := &Server{
		ShortCodeGenerator: fakeShortCodeGenerator(),
		KeyStore:           keyStore,
		Output:             os.Stdout,
		Logger:             createTestLogger(),
	}
	server.SetupRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "root page should return OK")
}

func TestRoot_NotPaired_ShowsForm(t *testing.T) {
	router := gin.Default()
	keyStore, _ := createTestKeyStore(t)
	server := &Server{
		ShortCodeGenerator: fakeShortCodeGenerator(),
		KeyStore:           keyStore,
		Output:             os.Stdout,
		Logger:             createTestLogger(),
	}
	server.SetupRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	router.ServeHTTP(w, req)

	body := w.Body.String()
	assert.Contains(t, body, "Sway RM", "should show title")
	assert.Contains(t, body, `<form id="pair-form"`, "should show pairing form")
	assert.Contains(t, body, `type="text"`, "should have code input")
}

func TestRoot_NotPaired_DoesNotShowPaired(t *testing.T) {
	router := gin.Default()
	keyStore, _ := createTestKeyStore(t)
	server := &Server{
		Logger:   createTestLogger(),
		KeyStore: keyStore,
	}
	server.SetupRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	router.ServeHTTP(w, req)

	body := w.Body.String()
	assert.NotContains(t, body, "Paired", "unpaired state should not show Paired message")
}

func TestPair_ValidShortCode_ReturnsAPIKey(t *testing.T) {
	expectedKey := "123456"
	router := gin.Default()
	keyStore, _ := createTestKeyStore(t)
	server := &Server{
		Logger:   createTestLogger(),
		KeyStore: keyStore,
		APICodeGenerator: func() string {
			return expectedKey
		},
	}
	server.SetupRoutes(router)
	server.currentPairingCode = "123456"

	w := httptest.NewRecorder()
	shortCode := url.Values{}
	shortCode.Set("short-code", "123456")
	encodedBody := strings.NewReader(shortCode.Encode())
	req, _ := http.NewRequest("POST", "/api/pair", encodedBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	router.ServeHTTP(w, req)

	var apiKeyCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "api-key" {
			apiKeyCookie = c
			break
		}
	}

	assert.NotNil(t, apiKeyCookie)
	assert.Equal(t, expectedKey, apiKeyCookie.Value, "the api-key cookie should contain API key")
}

func TestRoot_Paired_ShowPairedMessage(t *testing.T) {
	router := gin.Default()
	keyStore, _ := createTestKeyStore(t)
	server := &Server{
		Logger:             createTestLogger(),
		ShortCodeGenerator: fakeShortCodeGenerator(),
		KeyStore:           keyStore,
		pairingCodeExpiry:  time.Now().Add(1 * time.Hour),
	}
	server.SetupRoutes(router)

	apiKey := "some-valid-key"
	keyStore.StoreAPIKey(apiKey, time.Now().Add(1*time.Hour))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)

	req.AddCookie(&http.Cookie{
		Name:  "api-key",
		Value: apiKey,
	})

	router.ServeHTTP(w, req)

	body := w.Body.String()
	assert.NotContains(t, body, `<form id="pair-form"`, "paired state should not show the pairing form")
	assert.Contains(t, body, "Paired", "the state should be paired if the correct cookie is available")
}

func TestRoot_ServerCookieTTLReached_ShowExpiredMessage(t *testing.T) {
	router := gin.Default()
	keyStore, _ := createTestKeyStore(t)
	server := &Server{
		Logger:             createTestLogger(),
		ShortCodeGenerator: fakeShortCodeGenerator(),
		KeyStore:           keyStore,
		Output:             os.Stdout,
	}
	server.SetupRoutes(router)

	apiKey := "expired-key"
	keyStore.StoreAPIKey(apiKey, time.Now().Add(-1*time.Hour))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)

	req.AddCookie(&http.Cookie{
		Name:  "api-key",
		Value: apiKey,
	})

	router.ServeHTTP(w, req)

	body := w.Body.String()
	assert.Contains(t, body, "expired", "should show expired message")
	assert.Contains(t, body, `<form id="pair-form"`, "expired state should show the pairing form")
}

func TestPair_InvalidShortCode_ShowsError(t *testing.T) {
	router := gin.Default()
	keyStore, _ := createTestKeyStore(t)
	server := &Server{
		Logger:           createTestLogger(),
		KeyStore:         keyStore,
		APICodeGenerator: func() string { return "test-key" },
	}
	server.SetupRoutes(router)

	shortCode := url.Values{}
	shortCode.Set("short-code", "wrong-code")
	encodedBody := strings.NewReader(shortCode.Encode())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/pair", encodedBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	router.ServeHTTP(w, req)

	body := w.Body.String()
	assert.Contains(t, body, "Invalid pairing code", "should show error message")
	assert.Contains(t, body, `<form id="pair-form"`, "should show form again")
}

func TestValidateAndSaveAPIKey_ValidShortCode_CookieMatchesKeyStore(t *testing.T) {
	apiKey := "an-api-code"
	ks, _ := createTestKeyStore(t)
	validShortCode := "a-valid-short-code"
	scg := func() string { return validShortCode }
	acg := func() string { return apiKey }
	router := gin.Default()
	testLogger := log.New(os.Stderr, "", 0)
	server := NewServer(ks, scg, acg, os.Stdout, testLogger)
	server.currentPairingCode = validShortCode
	server.SetupRoutes(router)

	shortCode := url.Values{}
	shortCode.Set("short-code", validShortCode)
	encodedBody := strings.NewReader(shortCode.Encode())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/pair", encodedBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	router.ServeHTTP(w, req)
	apiKeyInKs, err := ks.GetAPIKey(apiKey)
	if err != nil {
		assert.Fail(t, "api key not in the key store")
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == apiKeyCookieName {
			cookie = c
			break
		}
	}

	assert.NotNil(t, apiKeyInKs)
	assert.Equal(t, apiKeyInKs.Key, cookie.Value, "cookie should be same value as stored in keystore")
}

func TestRoot_NotPaired_DoesNotRegeneratePairingCodeIfAlreadySet(t *testing.T) {
	router := gin.Default()
	callCount := 0
	keyStore, _ := createTestKeyStore(t)
	server := &Server{
		Logger: createTestLogger(),
		ShortCodeGenerator: func() string {
			callCount++
			return fmt.Sprintf("code-%d", callCount)
		},
		KeyStore: keyStore,
	}
	server.currentPairingCode = "existing-code"
	server.pairingCodeExpiry = time.Now().Add(1 * time.Hour)
	server.SetupRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, "existing-code", server.currentPairingCode, "should not regenerate pairing code if already set")
	assert.Equal(t, 0, callCount, "generator should not be called if code already exists")
}

func TestRoot_NotPaired_RegeneratesPairingCodeIfExpired(t *testing.T) {
	router := gin.Default()
	callCount := 0
	keyStore, _ := createTestKeyStore(t)
	server := &Server{
		Logger: createTestLogger(),
		ShortCodeGenerator: func() string {
			callCount++
			return fmt.Sprintf("code-%d", callCount)
		},
		KeyStore: keyStore,
	}
	server.currentPairingCode = "expired-code"
	server.pairingCodeExpiry = time.Now().Add(-10 * time.Minute)
	server.SetupRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	router.ServeHTTP(w, req)

	assert.NotEqual(t, "expired-code", server.currentPairingCode, "should regenerate expired pairing code")
	assert.Equal(t, "code-1", server.currentPairingCode, "should generate new code")
	assert.Equal(t, 1, callCount, "generator should be called once for expired code")
	assert.True(t, server.pairingCodeExpiry.After(time.Now()), "new code should have future expiry")
}

func TestRoot_NotPaired_PrintsPairingCodeWhenGenerated(t *testing.T) {
	router := gin.Default()
	keyStore, _ := createTestKeyStore(t)

	var output bytes.Buffer
	server := &Server{
		Logger:             createTestLogger(),
		ShortCodeGenerator: func() string { return "987654" },
		KeyStore:           keyStore,
		Output:             &output,
	}
	server.SetupRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	router.ServeHTTP(w, req)

	printed := output.String()
	assert.Contains(t, printed, "987654", "should print the generated pairing code")
	assert.Contains(t, printed, "Pairing code", "should include descriptive text")
}

func TestPair_ValidShortCode_InvalidatesPairingCode(t *testing.T) {
	router := gin.Default()
	keyStore, _ := createTestKeyStore(t)
	server := &Server{
		ShortCodeGenerator: fakeShortCodeGenerator(),
		APICodeGenerator:   func() string { return "test-api-key" },
		KeyStore:           keyStore,
		Output:             os.Stdout,
		Logger:             createTestLogger(),
	}
	server.currentPairingCode = "single-use"
	server.SetupRoutes(router)

	shortCode := url.Values{}
	shortCode.Set("short-code", "single-use")
	encodedBody := strings.NewReader(shortCode.Encode())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/pair", encodedBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "first pairing should succeed")
	assert.Empty(t, server.currentPairingCode, "pairing code should be cleared after successful use")

	w2 := httptest.NewRecorder()
	encodedBody2 := strings.NewReader(shortCode.Encode())
	req2, _ := http.NewRequest("POST", "/api/pair", encodedBody2)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w2, req2)

	body := w2.Body.String()
	assert.Contains(t, body, "Invalid pairing code", "second attempt with same code should fail")
}

func TestServer_IsShortCodeSet_ReturnsTrueWhenCodeExists(t *testing.T) {
	server := &Server{}

	assert.False(t, server.isShortCodeSet(), "should return false when code is empty")

	server.currentPairingCode = "test-code"
	assert.True(t, server.isShortCodeSet(), "should return true when code is set")
}

func TestServer_HasShortCodeExpired_ReturnsTrueWhenExpired(t *testing.T) {
	server := &Server{}

	server.pairingCodeExpiry = time.Now().Add(-1 * time.Minute)
	assert.True(t, server.hasShortCodeExpired(), "should return true when expired")

	server.pairingCodeExpiry = time.Now().Add(1 * time.Minute)
	assert.False(t, server.hasShortCodeExpired(), "should return false when not expired")
}

func TestPairRefreshMiddleware_ValidAPIKey_ExtendsExpiryBy30Minutes(t *testing.T) {
	router := gin.Default()
	keyStore, _ := createTestKeyStore(t)
	server := &Server{
		ShortCodeGenerator: fakeShortCodeGenerator(),
		KeyStore:           keyStore,
		pairingCodeExpiry:  time.Now().Add(1 * time.Hour),
		Logger:             createTestLogger(),
	}
	server.SetupRoutes(router)

	apiKey := "sliding-window-key"
	initialExpiry := time.Now().Add(1 * time.Hour)
	keyStore.StoreAPIKey(apiKey, initialExpiry)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/status", nil)
	req.AddCookie(&http.Cookie{
		Name:  "api-key",
		Value: apiKey,
	})

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "should return OK for valid API key")

	updatedKey, err := keyStore.GetAPIKey(apiKey)
	assert.NoError(t, err, "should retrieve API key from store")
	assert.NotNil(t, updatedKey)

	expectedExpiry := time.Now().Add(90 * time.Minute)
	timeDelta := updatedKey.TTL.Sub(expectedExpiry).Abs()
	assert.True(t, timeDelta < 2*time.Second, "expiry should be ~1.5 hours from now (initial 1h + refresh 30min)")
}

func TestPair_StoreAPIKeyFails_ReturnsInternalServerError(t *testing.T) {
	router := gin.Default()
	keyStore, db := createTestKeyStore(t)

	server := &Server{
		KeyStore:         keyStore,
		APICodeGenerator: func() string { return "test-key" },
		Logger:           createTestLogger(),
	}
	server.currentPairingCode = "valid-code"
	server.SetupRoutes(router)

	db.Close()

	shortCode := url.Values{}
	shortCode.Set("short-code", "valid-code")
	encodedBody := strings.NewReader(shortCode.Encode())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/pair", encodedBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code, "should return 500 when StoreAPIKey fails")
}

func TestPairRefreshMiddleware_DatabaseClosed_ContinuesGracefully(t *testing.T) {
	router := gin.Default()
	keyStore, db := createTestKeyStore(t)
	server := &Server{
		ShortCodeGenerator: fakeShortCodeGenerator(),
		KeyStore:           keyStore,
		pairingCodeExpiry:  time.Now().Add(1 * time.Hour),
		Logger:             createTestLogger(),
	}
	server.SetupRoutes(router)

	apiKey := "test-key"
	initialExpiry := time.Now().Add(1 * time.Hour)
	keyStore.StoreAPIKey(apiKey, initialExpiry)

	db.Close()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/status", nil)
	req.AddCookie(&http.Cookie{
		Name:  "api-key",
		Value: apiKey,
	})

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "middleware should continue gracefully when DB is closed (GetAPIKey fails, returns 401)")
}

func TestPairRefreshMiddleware_StoreAPIKeyFails_LogsError(t *testing.T) {
	var logOutput bytes.Buffer
	testLogger := log.New(&logOutput, "", 0)

	router := gin.Default()
	realKeyStore, db := createTestKeyStore(t)

	apiKey := "test-key"
	initialExpiry := time.Now().Add(1 * time.Hour)
	realKeyStore.StoreAPIKey(apiKey, initialExpiry)

	wrappedKeyStore := &testKeyStoreWrapper{
		KeyStore: realKeyStore,
		onStoreAPIKey: func() {
			db.Close()
		},
	}

	server := &Server{
		ShortCodeGenerator: fakeShortCodeGenerator(),
		KeyStore:           wrappedKeyStore,
		Logger:             testLogger,
		pairingCodeExpiry:  time.Now().Add(1 * time.Hour),
	}
	server.SetupRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/status", nil)
	req.AddCookie(&http.Cookie{
		Name:  "api-key",
		Value: apiKey,
	})

	router.ServeHTTP(w, req)

	logContents := logOutput.String()
	assert.Contains(t, logContents, "failed to refresh API key TTL", "should log error when StoreAPIKey fails")
}

type testKeyStoreWrapper struct {
	*security.KeyStore
	onStoreAPIKey func()
}

func (w *testKeyStoreWrapper) StoreAPIKey(apiKey string, expiresAt time.Time) error {
	if w.onStoreAPIKey != nil {
		w.onStoreAPIKey()
	}
	return w.KeyStore.StoreAPIKey(apiKey, expiresAt)
}
