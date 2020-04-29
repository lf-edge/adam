// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
	"github.com/lf-edge/eve/api/go/register"
)

type apiHandler struct {
	manager     driver.DeviceManager
	logChannel  chan *logs.LogBundle
	infoChannel chan *info.ZInfoMsg
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
		_, invalidCert := err.(*driver.InvalidCertError)
		_, invalidSerial := err.(*driver.InvalidSerialError)
		_, usedSerial := err.(*driver.UsedSerialError)
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
	// we do not keep the uuid or send it back; perhaps a future version of the API will support it
	_, err = h.manager.DeviceRegister(deviceCert, onboardCert, serial)
	if err != nil {
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
	_, err := h.manager.DeviceCheckCert(cert)
	if err != nil {
		log.Printf("error checking device cert: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
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
	config, err := h.manager.GetConfigResponse(*u)
	if err != nil {
		log.Printf("error getting device config: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	configRequest, err := getClientConfigRequest(r)
	if err != nil {
		log.Printf("error getting config request: %v", err)
	} else {
		//compare received config hash with current
		if strings.Compare(configRequest.ConfigHash, config.ConfigHash) == 0 {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	out, err := proto.Marshal(config)
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

func (h *apiHandler) info(w http.ResponseWriter, r *http.Request) {
	// only uses the device cert
	cert := getClientCert(r)
	_, err := h.manager.DeviceCheckCert(cert)
	if err != nil {
		log.Printf("error checking device cert: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
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
	case h.infoChannel <- msg:
	default:
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

func (h *apiHandler) metrics(w http.ResponseWriter, r *http.Request) {
	// only uses the device cert
	cert := getClientCert(r)
	_, err := h.manager.DeviceCheckCert(cert)
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

func (h *apiHandler) logs(w http.ResponseWriter, r *http.Request) {
	// only uses the device cert
	cert := getClientCert(r)
	_, err := h.manager.DeviceCheckCert(cert)
	if err != nil {
		log.Printf("error checking device cert: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
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
	case h.logChannel <- msg:
	default:
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
