package api

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/phasecurve/sway_rm/internal/security"
)

type Server struct {
	ShortCodeGenerator ShortCodeGenerator
	APICodeGenerator   APICodeGenerator
	KeyStore           *security.KeyStore
	Output             io.Writer
	currentPairingCode string
	pairingCodeExpiry  time.Time
}

func NewServer(keyStore *security.KeyStore, shortCodeGenerator ShortCodeGenerator, apiCodeGenerator APICodeGenerator, outputWriter io.Writer) *Server {
	return &Server{
		ShortCodeGenerator: shortCodeGenerator,
		APICodeGenerator:   apiCodeGenerator,
		KeyStore:           keyStore,
		Output:             outputWriter,
	}
}

func (s *Server) resetPairingCode() {
	s.currentPairingCode = ""
}

func (s *Server) publishShortCode() {
	fmt.Fprintf(s.Output, "\n\n\t\t%s%s%s\n\t\t%s Pairing code: %s %s\n\t\t%s%s%s\n\n", tl, strings.Repeat(hz, 22), tr, vr, s.getCurrentPairingCode(), vr, bl, strings.Repeat(hz, 22), br)
}

func (s *Server) setNewShortCodeExpiry() {
	s.pairingCodeExpiry = time.Now().Add(5 * time.Minute)
}

func (s *Server) setNewShortCode() {
	s.currentPairingCode = s.ShortCodeGenerator()
}

func (s *Server) hasShortCodeExpired() bool {
	return s.getPairingCodeExpiry().Before(time.Now())
}

func (s *Server) isShortCodeSet() bool {
	return s.getCurrentPairingCode() != ""
}

func (s *Server) getCurrentPairingCode() string {
	return s.currentPairingCode
}

func (s *Server) getPairingCodeExpiry() time.Time {
	return s.pairingCodeExpiry
}
