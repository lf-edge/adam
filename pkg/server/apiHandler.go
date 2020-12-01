// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/adam/pkg/driver/common"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
	"github.com/lf-edge/eve/api/go/register"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type ApiRequest struct {
	Timestamp time.Time `json:"timestamp"`
	UUID      uuid.UUID `json:"uuid,omitempty"`
	ClientIP  string    `json:"client-ip"`
	Forwarded string    `json:"forwarded,omitempty"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
}

type apiHandler struct {
	manager     driver.DeviceManager
	logChannel  chan []byte
	infoChannel chan []byte
}

func (h *apiHandler) recordClient(u *uuid.UUID, r *http.Request) {
	if u == nil {
		// we ignore non-device-specific requests for now
		log.Printf("error saving request for device without UUID")
		return
	}
	req := ApiRequest{
		Timestamp: time.Now(),
		UUID:      *u,
		ClientIP:  r.RemoteAddr,
		Forwarded: r.Header.Get("X-Forwarded-For"),
		Method:    r.Method,
		URL:       r.URL.String(),
	}
	b, err := json.Marshal(req)
	if err != nil {
		log.Printf("error saving request structure: %v", err)
		return
	}

	h.manager.WriteRequest(*u, b)
}

func (h *apiHandler) register(w http.ResponseWriter, r *http.Request) {
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
	err = h.manager.OnboardCheck(onboardCert, serial)
	if err != nil {
		_, invalidCert := err.(*common.InvalidCertError)
		_, invalidSerial := err.(*common.InvalidSerialError)
		_, usedSerial := err.(*common.UsedSerialError)
		switch {
		case invalidCert, invalidSerial:
			log.Printf("failed authentication %v", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
		case usedSerial:
			log.Printf("used serial %v", err)
			http.Error(w, err.Error(), http.StatusConflict)
		default:
			log.Printf("Error checking onboard cert and serial: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}
	// the passed cert is base64 encoded PEM. So we need to base64 decode it, and then extract the DER bytes
	// register the new device cert
	certPemBytes, err := base64.StdEncoding.DecodeString(string(msg.PemCert))
	if err != nil {
		log.Printf("error base64-decoding device certficate from registration: %v", err)
		http.Error(w, "error base64-decoding device certificate", http.StatusBadRequest)
		return
	}

	certDer, _ := pem.Decode(certPemBytes)
	deviceCert, err := x509.ParseCertificate(certDer.Bytes)
	if err != nil {
		log.Printf("unable to convert device cert data from message to x509 certificate: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	// generate a new uuid
	unew, err := uuid.NewV4()
	if err != nil {
		log.Printf("error generating a new device UUID: %v", err)
		http.Error(w, fmt.Sprintf("error generating a new device UUID: %v", err), http.StatusBadRequest)
		return
	}
	// we do not keep the uuid or send it back; perhaps a future version of the API will support it
	if err := h.manager.DeviceRegister(unew, deviceCert, onboardCert, serial, common.CreateBaseConfig(unew)); err != nil {
		log.Printf("error registering new device: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// send back a 201
	w.WriteHeader(http.StatusCreated)
}

func (h *apiHandler) probe(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s requested probe", r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
}

func (h *apiHandler) ping(w http.ResponseWriter, r *http.Request) {
	// only uses the device cert
	cert := getClientCert(r)
	u, err := h.manager.DeviceCheckCert(cert)
	if err != nil {
		log.Printf("error checking device cert: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	h.recordClient(u, r)
	// now just return a 200
	w.WriteHeader(http.StatusOK)
}

func (h *apiHandler) configPost(w http.ResponseWriter, r *http.Request) {
	// only uses the device cert
	cert := getClientCert(r)
	u, err := h.manager.DeviceCheckCert(cert)
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
	h.recordClient(u, r)
	conf, err := h.manager.GetConfig(*u)
	if err != nil {
		log.Printf("error getting device config: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// convert config into a protobuf
	var msg config.EdgeDevConfig
	if err := protojson.Unmarshal(conf, &msg); err != nil {
		log.Printf("error reading device config: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	response := &config.ConfigResponse{}

	hash := sha256.New()
	common.ComputeConfigElementSha(hash, &msg)
	configHash := hash.Sum(nil)

	response.Config = &msg
	response.ConfigHash = base64.URLEncoding.EncodeToString(configHash)

	configRequest, err := getClientConfigRequest(r)
	if err != nil {
		log.Printf("error getting config request: %v", err)
	} else {
		//compare received config hash with current
		if strings.Compare(configRequest.ConfigHash, response.ConfigHash) == 0 {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	out, err := proto.Marshal(response)
	if err != nil {
		log.Printf("error converting config to byte message: %v", err)
	}
	w.Header().Add(contentType, mimeProto)
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

func (h *apiHandler) config(w http.ResponseWriter, r *http.Request) {
	// only uses the device cert
	cert := getClientCert(r)
	u, err := h.manager.DeviceCheckCert(cert)
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
	h.recordClient(u, r)
	config, err := h.manager.GetConfig(*u)
	if err != nil {
		log.Printf("error getting device config: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Add(contentType, mimeProto)
	w.WriteHeader(http.StatusOK)
	w.Write(config)
}

func (h *apiHandler) info(w http.ResponseWriter, r *http.Request) {
	// only uses the device cert
	cert := getClientCert(r)
	u, err := h.manager.DeviceCheckCert(cert)
	if err != nil {
		log.Printf("error checking device cert: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	h.recordClient(u, r)
	b, err := ioutil.ReadAll(r.Body)
	if err != nil || len(b) == 0 {
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
	select {
	case h.infoChannel <- b:
	default:
	}
	err = h.manager.WriteInfo(*u, b)
	if err != nil {
		log.Printf("Failed to write info message: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// send back a 201
	w.WriteHeader(http.StatusCreated)
}

func (h *apiHandler) metrics(w http.ResponseWriter, r *http.Request) {
	// only uses the device cert
	cert := getClientCert(r)
	u, err := h.manager.DeviceCheckCert(cert)
	if err != nil {
		log.Printf("error checking device cert: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	h.recordClient(u, r)
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
	err = h.manager.WriteMetrics(*u, b)
	if err != nil {
		log.Printf("Failed to write metrics message: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// send back a 201
	w.WriteHeader(http.StatusCreated)
}

func (h *apiHandler) logs(w http.ResponseWriter, r *http.Request) {
	// only uses the device cert
	cert := getClientCert(r)
	u, err := h.manager.DeviceCheckCert(cert)
	if err != nil {
		log.Printf("error checking device cert: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	h.recordClient(u, r)
	b, err := ioutil.ReadAll(r.Body)
	if err != nil || len(b) == 0 {
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
	select {
	case h.logChannel <- b:
	default:
	}
	eveVersion := msg.GetEveVersion()
	image := msg.GetImage()
	var buf bytes.Buffer
	for _, entry := range msg.GetLog() {
		entry := &common.FullLogEntry{
			LogEntry:   entry,
			Image:      image,
			EveVersion: eveVersion,
		}
		// convert the message to bytes
		entryBytes, err := entry.Json()
		if err != nil {
			log.Printf("failed to marshal protobuf message into json: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		buf.Write(entryBytes)
	}

	err = h.manager.WriteLogs(*u, buf.Bytes())
	if err != nil {
		log.Printf("Failed to write logbundle message: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// send back a 201
	w.WriteHeader(http.StatusCreated)
}

func (h *apiHandler) appLogs(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.FromString(mux.Vars(r)["uuid"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// only uses the device cert
	cert := getClientCert(r)
	u, err := h.manager.DeviceCheckCert(cert)
	if u == nil {
		log.Printf("unknown device cert")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf("error checking device cert: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	h.recordClient(u, r)
	b, err := ioutil.ReadAll(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error reading request body: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	msg := &logs.AppInstanceLogBundle{}
	if err := proto.Unmarshal(b, msg); err != nil {
		log.Printf("Failed to parse appinstancelogbundle message: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	select {
	case h.logChannel <- b:
	default:
	}
	err = h.manager.WriteAppInstanceLogs(uid, *u, b)
	if err != nil {
		log.Printf("Failed to write appinstancelogbundle message: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// send back a 201
	w.WriteHeader(http.StatusCreated)
}

// retrieve the config request
func getClientConfigRequest(r *http.Request) (*config.ConfigRequest, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Body read failed: %v", err)
		return nil, err
	}
	configRequest := &config.ConfigRequest{}
	err = proto.Unmarshal(body, configRequest)
	if err != nil {
		log.Printf("Unmarshalling failed: %v", err)
		return nil, err
	}
	return configRequest, nil
}
