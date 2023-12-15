// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/adam/pkg/driver/common"
	"github.com/lf-edge/eve-api/go/config"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/proto"
)

type apiHandler struct {
	manager       driver.DeviceManager
	logChannel    chan []byte
	infoChannel   chan []byte
	metricChannel chan []byte
}

// GetUser godoc
// @Summary Retrieves user based on given ID
// @Produce json
// @Param id path integer true "User ID"
// @Success 200 {object} models.User
// @Router /users/{id} [get]
func (h *apiHandler) recordClient(u *uuid.UUID, r *http.Request) {
	if u == nil {
		// we ignore non-device-specific requests for now
		log.Printf("error saving request for device without UUID")
		return
	}
	req := common.ApiRequest{
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

func (h *apiHandler) checkCertAndRecord(w http.ResponseWriter, r *http.Request) *uuid.UUID {
	// only uses the device cert
	cert := getClientCert(r)
	u, err := h.manager.DeviceCheckCert(cert)
	if err != nil {
		log.Printf("error checking device cert: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	if u == nil {
		log.Printf("unknown device cert")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return nil
	}
	h.recordClient(u, r)
	return u
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
	status, err := registerProcess(h.manager, b, onboardCert)
	if err != nil {
		log.Printf("Failed in registerProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

func (h *apiHandler) probe(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s requested probe", r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
}

func (h *apiHandler) ping(w http.ResponseWriter, r *http.Request) {
	if devID := h.checkCertAndRecord(w, r); devID == nil {
		return
	}
	// now just return a 200
	w.WriteHeader(http.StatusOK)
}

func (h *apiHandler) configPost(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	cfg, err := h.manager.GetConfig(*u)
	if err != nil {
		log.Printf("error getting device config: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	configRequest, err := h.getClientConfigRequest(r)
	if err != nil {
		log.Printf("error getting config request: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	data, code, err := configProcess(h.manager, *u, configRequest, cfg, false)
	if err != nil {
		log.Printf("error configProcess: %v", err)
		http.Error(w, http.StatusText(code), code)
		return
	}
	if code == http.StatusNotModified {
		w.WriteHeader(code)
		return
	}
	w.Header().Add(contentType, mimeProto)
	w.WriteHeader(code)
	w.Write(data)
}

func (h *apiHandler) config(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	cfg, err := h.manager.GetConfig(*u)
	if err != nil {
		log.Printf("error getting device config: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Add(contentType, mimeProto)
	w.WriteHeader(http.StatusOK)
	w.Write(cfg)
}

func (h *apiHandler) info(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error reading request body: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	status, err := infoProcess(h.manager, h.infoChannel, *u, b)
	if err != nil {
		log.Printf("Failed to infoProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

func (h *apiHandler) metrics(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("error reading request body: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	status, err := metricProcess(h.manager, h.metricChannel, *u, b)
	if err != nil {
		log.Printf("Failed to metricProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

func (h *apiHandler) logs(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error reading request body: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	status, err := logsProcess(h.manager, h.logChannel, *u, b)
	if err != nil {
		log.Printf("Failed to logsProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

func (h *apiHandler) newLogs(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}

	status, err := newLogsProcess(h.manager, h.logChannel, *u, r.Body)
	if err != nil {
		log.Printf("Failed to logsProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

func (h *apiHandler) appLogs(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	uid, err := uuid.FromString(mux.Vars(r)["uuid"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error reading request body: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	status, err := appLogsProcess(h.manager, *u, uid, b)
	if err != nil {
		log.Printf("Failed to logsProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

func (h *apiHandler) uuid(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	uuidResponce, err := h.manager.GetUUID(*u)
	if err != nil {
		log.Printf("error getting device uuidResponce: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Add(contentType, mimeProto)
	w.WriteHeader(http.StatusOK)
	w.Write(uuidResponce)
}

func (h *apiHandler) newAppLogs(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	uid, err := uuid.FromString(mux.Vars(r)["uuid"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	status, err := newAppLogsProcess(h.manager, *u, uid, r.Body)
	if err != nil {
		log.Printf("Failed to logsProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

// retrieve the config request
func (h *apiHandler) getClientConfigRequest(r *http.Request) (*config.ConfigRequest, error) {
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

func (h *apiHandler) flowLog(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error reading request body: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	status, err := flowLogProcess(h.manager, *u, b)
	if err != nil {
		log.Printf("Failed to logsProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}
