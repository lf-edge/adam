package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/zededa/adam/pkg/driver"
)

// Server an adam server
type Server struct {
	Port          string
	CertPath      string
	KeyPath       string
	DeviceManager driver.DeviceManager
	CertRefresh   int
}

// Start start the server
func (s *Server) Start() {
	// ensure the server cert and key exist
	_, err := os.Stat(s.CertPath)
	if err != nil {
		log.Fatalf("server cert %s does not exist", s.CertPath)
	}
	_, err = os.Stat(s.KeyPath)
	if err != nil {
		log.Fatalf("server key %s does not exist", s.KeyPath)
	}

	if s.DeviceManager == nil {
		log.Fatalf("empty device manager")
	}

	// save the device manager settings
	s.DeviceManager.SetCacheTimeout(s.CertRefresh)

	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(notFound)

	// edgedevice endpoint - fully compliant with EVE open API
	api := &apiHandler{
		manager: s.DeviceManager,
	}

	ed := router.PathPrefix("/api/v1/edgedevice").Subrouter()
	ed.Use(ensureMTLS)
	ed.Use(logRequest)
	ed.HandleFunc("/register", api.register).Methods("POST")
	ed.HandleFunc("/ping", api.ping).Methods("GET")
	ed.HandleFunc("/config", api.config).Methods("GET")
	ed.HandleFunc("/info", api.info).Methods("POST")
	ed.HandleFunc("/metrics", api.metrics).Methods("POST")
	ed.HandleFunc("/logs", api.logs).Methods("POST")

	// admin endpoint - custom, used to manage adam
	admin := &adminHandler{
		manager: s.DeviceManager,
	}

	ad := router.PathPrefix("/admin").Subrouter()
	ad.HandleFunc("/onboard", admin.onboardList).Methods("GET")
	ad.HandleFunc("/onboard/{cn}", admin.onboardGet).Methods("GET")
	ad.HandleFunc("/onboard", admin.onboardAdd).Methods("POST")
	ad.HandleFunc("/onboard", admin.onboardClear).Methods("DELETE")
	ad.HandleFunc("/onboard/{cn}", admin.onboardRemove).Methods("DELETE")
	ad.HandleFunc("/device", admin.deviceList).Methods("GET")
	ad.HandleFunc("/device/{uuid}", admin.deviceGet).Methods("GET")
	ad.HandleFunc("/device/{uuid}/config", admin.deviceConfigGet).Methods("GET")
	ad.HandleFunc("/device/{uuid}/config", admin.deviceConfigSet).Methods("PUT")
	ad.HandleFunc("/device", admin.deviceAdd).Methods("POST")
	ad.HandleFunc("/device", admin.deviceClear).Methods("DELETE")
	ad.HandleFunc("/device/{uuid}", admin.deviceRemove).Methods("DELETE")

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequestClientCert,
	}

	server := &http.Server{
		Handler:   router,
		Addr:      fmt.Sprintf(":%s", s.Port),
		TLSConfig: tlsConfig,
	}
	log.Println("Starting adam:")
	log.Printf("\tPort: %s\n", s.Port)
	log.Printf("\tstorage: %s\n", s.DeviceManager.Name())
	log.Printf("\tdatabase: %s\n", s.DeviceManager.Database())
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

func notFound(w http.ResponseWriter, r *http.Request) {
	log.Printf("404 returned for %s", r.URL.Path)
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}
