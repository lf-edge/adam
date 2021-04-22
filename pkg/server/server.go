// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/adam/web"
)

// Server an adam server
type Server struct {
	Port            string
	Address         string
	CertPath        string
	KeyPath         string
	SigningCertPath string
	SigningKeyPath  string
	EncryptCertPath string
	EncryptKeyPath  string
	DeviceManager   driver.DeviceManager
	CertRefresh     int
	// WebDir path to webfiles to serve. If empty, use embedded
	WebDir string
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
	//we need certificates to work under apiV2
	hasApiV2 := true
	_, err = os.Stat(s.SigningCertPath)
	if err != nil {
		hasApiV2 = false
		log.Printf("signing cert %s does not exist", s.CertPath)
	}
	_, err = os.Stat(s.SigningKeyPath)
	if hasApiV2 && err != nil {
		hasApiV2 = false
		log.Printf("signing key %s does not exist", s.KeyPath)
	}
	_, err = os.Stat(s.EncryptCertPath)
	if hasApiV2 && err != nil {
		hasApiV2 = false
		log.Printf("encrypt cert %s does not exist", s.CertPath)
	}
	_, err = os.Stat(s.EncryptKeyPath)
	if hasApiV2 && err != nil {
		hasApiV2 = false
		log.Printf("encrypt key %s does not exist", s.KeyPath)
	}

	if s.DeviceManager == nil {
		log.Fatalf("empty device manager")
	}

	// save the device manager settings
	s.DeviceManager.SetCacheTimeout(s.CertRefresh)

	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(notFound)

	sh := http.StripPrefix("/swaggerui/", http.FileServer(http.Dir("/swaggerui/")))
	router.PathPrefix("/swaggerui/").Handler(sh)

	// to pass logs and info around
	logChannel := make(chan []byte)
	infoChannel := make(chan []byte)
	metricChannel := make(chan []byte)

	// edgedevice endpoint - fully compliant with EVE open API
	api := &apiHandler{
		manager:       s.DeviceManager,
		logChannel:    logChannel,
		infoChannel:   infoChannel,
		metricChannel: metricChannel,
	}

	router.HandleFunc("/probe", api.probe).Methods("GET")

	ed := router.PathPrefix("/api/v1/edgedevice").Subrouter()
	ed.Use(ensureMTLS)
	ed.Use(logRequest)
	ed.HandleFunc("/register", api.register).Methods("POST")
	ed.HandleFunc("/ping", api.ping).Methods("GET")
	ed.HandleFunc("/config", api.config).Methods("GET")
	ed.HandleFunc("/config", api.configPost).Methods("POST")
	ed.HandleFunc("/info", api.info).Methods("POST")
	ed.HandleFunc("/metrics", api.metrics).Methods("POST")
	ed.HandleFunc("/logs", api.logs).Methods("POST")
	ed.HandleFunc("/newlogs", api.newLogs).Methods("POST")
	ed.HandleFunc("/apps/instances/id/{uuid}/logs", api.appLogs).Methods("POST")
	ed.HandleFunc("/apps/instanceid/id/{uuid}/newlogs", api.newAppLogs).Methods("POST")

	if hasApiV2 {
		apiv2 := &apiHandlerv2{
			manager:         s.DeviceManager,
			logChannel:      logChannel,
			infoChannel:     infoChannel,
			metricChannel:   metricChannel,
			signingCertPath: s.SigningCertPath,
			signingKeyPath:  s.SigningKeyPath,
			encryptCertPath: s.EncryptCertPath,
			encryptKeyPath:  s.EncryptKeyPath,
		}

		edv2 := router.PathPrefix("/api/v2/edgedevice").Subrouter()
		edv2.Use(ensureMTLS)
		edv2.Use(logRequest)
		edv2.HandleFunc("/certs", apiv2.certs).Methods("GET")
		edv2.HandleFunc("/certs", apiv2.certs).Methods("POST")
		edv2.HandleFunc("/register", apiv2.register).Methods("POST")
		edv2.HandleFunc("/ping", apiv2.ping).Methods("GET")
		edv2.HandleFunc("/config", apiv2.config).Methods("GET")
		edv2.HandleFunc("/config", apiv2.configPost).Methods("POST")
		edv2.HandleFunc("/id/{uuid}/config", apiv2.config).Methods("GET")
		edv2.HandleFunc("/id/{uuid}/config", apiv2.configPost).Methods("POST")
		edv2.HandleFunc("/id/{uuid}/attest", apiv2.attest).Methods("POST")
		edv2.HandleFunc("/id/{uuid}/info", apiv2.info).Methods("POST")
		edv2.HandleFunc("/id/{uuid}/metrics", apiv2.metrics).Methods("POST")
		edv2.HandleFunc("/id/{uuid}/logs", apiv2.logs).Methods("POST")
		edv2.HandleFunc("/id/{uuid}/newlogs", apiv2.newLogs).Methods("POST")
		edv2.HandleFunc("/id/{uuid}/apps/instances/id/{appuuid}/logs", apiv2.appLogs).Methods("POST")
		edv2.HandleFunc("/id/{uuid}/apps/instanceid/{appuuid}/newlogs", apiv2.newAppLogs).Methods("POST")
	}

	// admin endpoint - custom, used to manage adam
	admin := &adminHandler{
		manager:     s.DeviceManager,
		logChannel:  logChannel,
		infoChannel: infoChannel,
	}

	ad := router.PathPrefix("/admin").Subrouter()
	// swagger:operation GET /onboard onboard
	//
	//
	// Onboards EVE
	//
	// The EVE should connect first
	//
	// ---
	// produces:
	// - application/json
	// tags:
	// - admin
	// responses:
	//   '200':
	//     description: successful operation
	ad.HandleFunc("/onboard", admin.onboardList).Methods("GET")
	ad.HandleFunc("/onboard/{cn}", admin.onboardGet).Methods("GET")
	ad.HandleFunc("/onboard", admin.onboardAdd).Methods("POST")
	ad.HandleFunc("/onboard", admin.onboardClear).Methods("DELETE")
	ad.HandleFunc("/onboard/{cn}", admin.onboardRemove).Methods("DELETE")
	ad.HandleFunc("/device", admin.deviceList).Methods("GET")
	ad.HandleFunc("/device/{uuid}", admin.deviceGet).Methods("GET")
	ad.HandleFunc("/device/{uuid}/config", admin.deviceConfigGet).Methods("GET")
	ad.HandleFunc("/device/{uuid}/config", admin.deviceConfigSet).Methods("PUT")
	ad.HandleFunc("/device/{uuid}/logs", admin.deviceLogsGet).Methods("GET")
	ad.HandleFunc("/device/{uuid}/info", admin.deviceInfoGet).Methods("GET")
	ad.HandleFunc("/device/{uuid}/requests", admin.deviceRequestsGet).Methods("GET")
	ad.HandleFunc("/device/{uuid}/certs", admin.deviceCertsGet).Methods("GET")
	ad.HandleFunc("/device", admin.deviceAdd).Methods("POST")
	ad.HandleFunc("/device", admin.deviceClear).Methods("DELETE")
	ad.HandleFunc("/device/{uuid}", admin.deviceRemove).Methods("DELETE")

	var (
		//index  []byte
		httpFS        fs.FS
		stripPrefix   string
		indexFilename string
	)
	if s.WebDir != "" {
		httpFS = os.DirFS(s.WebDir)
		stripPrefix = "/static/"
		indexFilename = "index.html"
	} else {
		httpFS = web.StaticFiles
		stripPrefix = "/"
		indexFilename = "static/index.html"
	}
	indexHandler := func(w http.ResponseWriter, r *http.Request) {
		filename := "index.html"
		f, err := httpFS.Open(indexFilename)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer f.Close()
		content, err := ioutil.ReadAll(f)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		http.ServeContent(w, r, filename, time.Now(), bytes.NewReader(content))
	}
	// / and /index.html go to the root
	router.HandleFunc("/", indexHandler).Methods("GET")
	router.HandleFunc("/index.html", indexHandler).Methods("GET")
	router.PathPrefix("/static/").Handler(http.StripPrefix(stripPrefix, http.FileServer(http.FS(httpFS))))

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  nil,
	}

	server := &http.Server{
		Handler:   router,
		Addr:      fmt.Sprintf("%s:%s", s.Address, s.Port),
		TLSConfig: tlsConfig,
	}
	log.Println("Starting adam:")
	log.Printf("\tURL: https://%s:%s\n", s.Address, s.Port)
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
