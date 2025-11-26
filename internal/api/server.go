package api

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/phasecurve/sway_rm/internal/security"
)

type Logger interface {
	Printf(format string, v ...interface{})
}

type Server struct {
	ShortCodeGenerator ShortCodeGenerator
	APICodeGenerator   APICodeGenerator
	KeyStore           security.KeyStorer
	Output             io.Writer
	Logger             Logger
	currentPairingCode string
	pairingCodeExpiry  time.Time
}

type ServerOption func(*Server)

func WithKeyStore(keyStore security.KeyStorer) ServerOption {
	return func(s *Server) {
		s.KeyStore = keyStore
	}
}

func WithShortCodeGenerator(gen ShortCodeGenerator) ServerOption {
	return func(s *Server) {
		s.ShortCodeGenerator = gen
	}
}

func WithAPICodeGenerator(gen APICodeGenerator) ServerOption {
	return func(s *Server) {
		s.APICodeGenerator = gen
	}
}

func WithOutput(output io.Writer) ServerOption {
	return func(s *Server) {
		s.Output = output
	}
}

func WithLogger(logger Logger) ServerOption {
	return func(s *Server) {
		s.Logger = logger
	}
}

func NewServer(opts ...ServerOption) *Server {
	s := &Server{
		ShortCodeGenerator: security.GenerateShortCode,
		APICodeGenerator:   security.GenerateAPIKey,
		Output:             os.Stdout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Server) resetPairingCode() {
	s.currentPairingCode = ""
}

func (s *Server) publishShortCode() {
	fmt.Fprintf(s.Output, `

		╔════════════════════════╗
		║  Pairing code: %s  ║
		╚════════════════════════╝

`, s.getCurrentPairingCode())
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
