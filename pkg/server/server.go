package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

type Server struct {
	Port                   string
	CertPath               string
	KeyPath                string
	DeviceDatabasePath     string
	OnboardingDatabasePath string
	CertRefresh            int
}

func (s *Server) Start() {
	// ensure we have an onboarding database
	if s.OnboardingDatabasePath == "" {
		log.Fatalf("onboarding path must be set")
	}
	fi, err := os.Stat(s.OnboardingDatabasePath)
	if err != nil {
		log.Fatalf("onboarding database path %s does not exist", s.OnboardingDatabasePath)
	}
	if !fi.IsDir() {
		log.Fatalf("onboarding database path %s is not a directory", s.OnboardingDatabasePath)
	}

	// ensure the server cert and key exist
	_, err = os.Stat(s.CertPath)
	if err != nil {
		log.Fatalf("server cert %s does not exist", s.CertPath)
	}
	_, err = os.Stat(s.KeyPath)
	if err != nil {
		log.Fatalf("server key %s does not exist", s.KeyPath)
	}

	// create a handler based on where our device database is
	// in the future, we may support other device manager types
	var mgr deviceManager
	if s.DeviceDatabasePath != "" {
		fi, err := os.Stat(s.DeviceDatabasePath)
		if os.IsNotExist(err) {
			log.Fatalf("device database path %s does not exist", s.DeviceDatabasePath)
		}
		if !fi.IsDir() {
			log.Fatalf("device database path %s is not a directory", s.DeviceDatabasePath)
		}
		mgr = &deviceManagerFile{
			devicePath:  s.DeviceDatabasePath,
			onboardPath: s.OnboardingDatabasePath,
		}
	} else {
		mgr = &deviceManagerMemory{}
	}

	// save the device manager settings
	mgr.SetCacheTimeout(s.CertRefresh)

	h := &requestHandler{
		manager: mgr,
	}

	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(notFound)

	ed := router.PathPrefix("/api/v1/edgedevice").Subrouter()
	ed.Use(ensureMTLS)
	ed.Use(logRequest)
	ed.HandleFunc("/register", h.register).Methods("POST")
	ed.HandleFunc("/ping", h.ping).Methods("GET")
	ed.HandleFunc("/config", h.config).Methods("GET")
	ed.HandleFunc("/info", h.info).Methods("POST")
	ed.HandleFunc("/metrics", h.metrics).Methods("POST")
	ed.HandleFunc("/logs", h.logs).Methods("POST")

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
	}

	server := &http.Server{
		Handler:   router,
		Addr:      fmt.Sprintf(":%s", s.Port),
		TLSConfig: tlsConfig,
	}
	log.Println("Starting adam:")
	log.Printf("\tPort: %s\n", s.Port)
	log.Printf("\tonboarding certs: %s\n", s.OnboardingDatabasePath)
	log.Printf("\tdevice database: %s\n", s.DeviceDatabasePath)
	log.Printf("\tserver cert: %s\n", s.CertPath)
	log.Printf("\tserver key: %s\n", s.KeyPath)
	log.Fatal(server.ListenAndServeTLS(s.CertPath, s.KeyPath))
}

// middleware handlers to check device cert and onboarding cert

// check that a known device cert has been presented
func ensureMTLS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ensure we have TLS with at least one PeerCertificate
		if r.TLS == nil {
			http.Error(w, "TLS required", http.StatusUnauthorized)
			return
		}
		if r.TLS.PeerCertificates == nil || len(r.TLS.PeerCertificates) < 1 {
			http.Error(w, "client TLS authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// log the request and client
func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cert := getClientCert(r)
		log.Printf("%s requested %s", cert.Subject.String(), r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// retrieve the client cert
func getClientCert(r *http.Request) *x509.Certificate {
	return r.TLS.PeerCertificates[0]
}

type requestHandler struct {
	manager deviceManager
}

func (h *requestHandler) register(w http.ResponseWriter, r *http.Request) {
	cert := getClientCert(r)
	io.WriteString(w, cert.Subject.String())
}

func (h *requestHandler) ping(w http.ResponseWriter, r *http.Request) {
}

func (h *requestHandler) config(w http.ResponseWriter, r *http.Request) {
}

func (h *requestHandler) info(w http.ResponseWriter, r *http.Request) {
}

func (h *requestHandler) metrics(w http.ResponseWriter, r *http.Request) {
}

func (h *requestHandler) logs(w http.ResponseWriter, r *http.Request) {
}

func notFound(w http.ResponseWriter, r *http.Request) {
	log.Printf("404 returned for %s", r.URL.Path)
	http.Error(w, "not found", http.StatusNotFound)
}
