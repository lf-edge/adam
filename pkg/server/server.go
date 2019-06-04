package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/gorilla/mux"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
	"github.com/lf-edge/eve/api/go/register"
)

const (
	contentType = "Content-Type"
	mimeProto   = "application/x-proto-binary"
)

// Server an adam server
type Server struct {
	Port        string
	CertPath    string
	KeyPath     string
	DatabaseURL string
	CertRefresh int
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

	// create a handler based on where our device database is
	// in the future, we may support other device manager types
	var mgr DeviceManager
	for _, m := range getDeviceManagers() {
		name := m.Name()
		valid, err := m.Init(s.DatabaseURL)
		if err != nil {
			log.Fatalf("error initializing the %s device manager: %v", name, err)
		}
		if valid {
			mgr = m
			break
		}
	}
	if mgr == nil {
		log.Fatalf("could not find valid device manager")
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
	log.Printf("\tstorage: %s\n", mgr.Name())
	log.Printf("\tdatabase: %s\n", s.DatabaseURL)
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
	manager DeviceManager
}

func (h *requestHandler) register(w http.ResponseWriter, r *http.Request) {
	// get the onboard cert and unpack the message to:
	//  - get the serial
	//  - get the device cert
	onboardCert := getClientCert(r)
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("error reading request body: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	msg := &register.ZRegisterMsg{}
	if err := proto.Unmarshal(b, msg); err != nil {
		log.Printf("Failed to parse register message: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	serial := msg.Serial
	valid, err := h.manager.CheckOnboardCert(onboardCert, serial)
	switch {
	case err != nil:
		log.Printf("Error checking onboard cert and serial: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	case !valid:
		log.Printf("failed authentication")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	// register the new device cert
	deviceCert, err := x509.ParseCertificate(msg.PemCert)
	if err != nil {
		log.Printf("unable to convert device cert data from message to x509 certificate: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	// we do not keep the uuid or send it back; perhaps a future version of the API will support it
	_, err = h.manager.RegisterDeviceCert(deviceCert, onboardCert, serial)
	if err != nil {
		log.Printf("error registering new device: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// send back a 201
	w.WriteHeader(http.StatusCreated)
}

func (h *requestHandler) ping(w http.ResponseWriter, r *http.Request) {
	// only uses the device cert
	cert := getClientCert(r)
	_, err := h.manager.CheckDeviceCert(cert)
	if err != nil {
		log.Printf("error checking device cert: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	// now just return a 200
	w.WriteHeader(http.StatusOK)
}

func (h *requestHandler) config(w http.ResponseWriter, r *http.Request) {
	// only uses the device cert
	cert := getClientCert(r)
	u, err := h.manager.CheckDeviceCert(cert)
	if err != nil {
		log.Printf("error checking device cert: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if u == nil {
		log.Printf("unknown device cert")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	config, err := h.manager.GetConfig(*u)
	if err != nil {
		log.Printf("error getting device config: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	out, err := proto.Marshal(config)
	if err != nil {
		log.Printf("error converting config to byte message: %v", err)
	}
	w.Header().Add(contentType, mimeProto)
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

func (h *requestHandler) info(w http.ResponseWriter, r *http.Request) {
	// only uses the device cert
	cert := getClientCert(r)
	_, err := h.manager.CheckDeviceCert(cert)
	if err != nil {
		log.Printf("error checking device cert: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("error reading request body: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	msg := &info.ZInfoMsg{}
	if err := proto.Unmarshal(b, msg); err != nil {
		log.Printf("Failed to parse info message: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	err = h.manager.WriteInfo(msg)
	if err != nil {
		log.Printf("Failed to write info message: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// send back a 201
	w.WriteHeader(http.StatusCreated)
}

func (h *requestHandler) metrics(w http.ResponseWriter, r *http.Request) {
	// only uses the device cert
	cert := getClientCert(r)
	_, err := h.manager.CheckDeviceCert(cert)
	if err != nil {
		log.Printf("error checking device cert: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("error reading request body: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	msg := &metrics.ZMetricMsg{}
	if err := proto.Unmarshal(b, msg); err != nil {
		log.Printf("Failed to parse metrics message: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	err = h.manager.WriteMetrics(msg)
	if err != nil {
		log.Printf("Failed to write metrics message: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// send back a 201
	w.WriteHeader(http.StatusCreated)
}

func (h *requestHandler) logs(w http.ResponseWriter, r *http.Request) {
	// only uses the device cert
	cert := getClientCert(r)
	_, err := h.manager.CheckDeviceCert(cert)
	if err != nil {
		log.Printf("error checking device cert: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("error reading request body: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	msg := &logs.LogBundle{}
	if err := proto.Unmarshal(b, msg); err != nil {
		log.Printf("Failed to parse logbundle message: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	err = h.manager.WriteLogs(msg)
	if err != nil {
		log.Printf("Failed to write logbundle message: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// send back a 201
	w.WriteHeader(http.StatusCreated)
}

func notFound(w http.ResponseWriter, r *http.Request) {
	log.Printf("404 returned for %s", r.URL.Path)
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}
