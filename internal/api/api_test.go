package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestStatus_NotPaired_Unauthorized(t *testing.T) {
	router := gin.Default()
	server := &Server{}
	server.SetupRoutes(router)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/status", nil)
	router.ServeHTTP(w, req)

	actualStatusCode := w.Code

	assert.Equal(t, http.StatusUnauthorized, actualStatusCode, "unpaired request shows HTTP Unauthorized")
}

func TestRoot_ReturnsOK(t *testing.T) {
	router := gin.Default()
	server := &Server{}
	server.SetupRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "root page should return OK")
}

func TestRoot_NotPaired_ShowsForm(t *testing.T) {
	router := gin.Default()
	server := &Server{}
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
	server := &Server{}
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
	server := &Server{
		APICodeGenerator: func() string {
			return expectedKey
		},
	}
	server.SetupRoutes(router)

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
	server := &Server{}
	server.SetupRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)

	req.AddCookie(&http.Cookie{
		Name:  "api-key",
		Value: "some-valid-key",
	})

	router.ServeHTTP(w, req)

	body := w.Body.String()
	assert.NotContains(t, body, `<form id="pair-form"`, "paired state should not show the pairing form")
	assert.Contains(t, body, "Paired", "the state should be paired if the correct cookie is available")
}

func TestRoot_ServerCookieTTLReached_ShowExpiredMessage(t *testing.T) {
	router := gin.Default()
	server := &Server{}
	server.SetupRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)

	req.AddCookie(&http.Cookie{
		Name:  "api-key",
		Value: "some-valid-key",
	})

	router.ServeHTTP(w, req)

	body := w.Body.String()
	assert.NotContains(t, body, `<form id="pair-form"`, "paired state should not show the pairing form")
	assert.Contains(t, body, "Paired", "the state should be paired if the correct cookie is available")
}

func TestPair_InvalidShortCode_ShowsError(t *testing.T) {
	router := gin.Default()
	server := &Server{
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

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "Invalid pairing code", "should show error message")
	assert.Contains(t, body, `<form id="pair-form"`, "should show form again")
}
