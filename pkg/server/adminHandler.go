// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/adam/pkg/driver/common"
	ax "github.com/lf-edge/adam/pkg/x509"
	"github.com/lf-edge/eve/api/go/config"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	StreamHeader = "X-Stream"
	StreamValue  = "true"
)

type adminHandler struct {
	manager         driver.DeviceManager
	logChannel      chan []byte
	infoChannel     chan []byte
	requestsChannel chan []byte
}

// OnboardCert encoding for sending an onboard cert and serials via json
// swagger:parameters onboard
type OnboardCert struct {
	// a Cert for onboarding
	//
	// unique: true
	// in: query
	Cert []byte
	// a Serial for onboarding
	//
	// unique: true
	// in: query
	Serial string
}

// DeviceCert encoding for sending a device information, including device cert, onboard cert, and serial, if any
type DeviceCert struct {
	Cert    []byte
	Onboard []byte
	Serial  string
}

func (h *adminHandler) onboardAdd(w http.ResponseWriter, r *http.Request) {
	// extract certificate and serials from request body
	contentType := r.Header.Get(contentType)
	if contentType != mimeJSON {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	decoder := json.NewDecoder(r.Body)
	var t OnboardCert
	err := decoder.Decode(&t)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	serials := strings.Split(t.Serial, ",")
	cert, err := ax.ParseCert(t.Cert)
	if err != nil {
		log.Printf("onboardAdd: ParseCert error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = h.manager.OnboardRegister(cert, serials)
	if err != nil {
		log.Printf("onboardAdd: OnboardRegister error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *adminHandler) onboardList(w http.ResponseWriter, r *http.Request) {
	cns, err := h.manager.OnboardList()
	if err != nil {
		log.Printf("onboardList: OnboardList error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body := strings.Join(cns, "\n")
	w.WriteHeader(http.StatusOK)
	w.Header().Add(contentType, mimeTextPlain)
	w.Write([]byte(body))
}

func (h *adminHandler) onboardGet(w http.ResponseWriter, r *http.Request) {
	cn := mux.Vars(r)["cn"]
	cert, serials, err := h.manager.OnboardGet(cn)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("onboardGet: OnboardGet(%s) error: %v", cn, err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	default:
		body, err := json.Marshal(OnboardCert{
			Cert:   ax.PemEncodeCert(cert.Raw),
			Serial: strings.Join(serials, ","),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}
}

func (h *adminHandler) onboardRemove(w http.ResponseWriter, r *http.Request) {
	cn := mux.Vars(r)["cn"]
	err := h.manager.OnboardRemove(cn)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("OnboardRemove(%s) error: %v", cn, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (h *adminHandler) onboardClear(w http.ResponseWriter, r *http.Request) {
	err := h.manager.OnboardClear()
	if err != nil {
		log.Printf("onboardClear: OnboardClear error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *adminHandler) deviceAdd(w http.ResponseWriter, r *http.Request) {
	// extract certificate and serials from request body
	contentType := r.Header.Get(contentType)
	if contentType != mimeTextPlain {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var (
		t       DeviceCert
		cert    *x509.Certificate
		onboard *x509.Certificate
	)
	err := decoder.Decode(&t)
	if err != nil {
		log.Printf("deviceAdd: Decode error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cert, err = ax.ParseCert(t.Cert)
	if err != nil {
		log.Printf("deviceAdd: ParseCert device error: %v", err)
		http.Error(w, fmt.Sprintf("bad device cert: %v", err), http.StatusBadRequest)
		return
	}
	if t.Onboard != nil && len(t.Onboard) > 0 {
		onboard, err = ax.ParseCert(t.Onboard)
		if err != nil {
			log.Printf("deviceAdd: ParseCert onboard error: %v", err)
			http.Error(w, fmt.Sprintf("bad onboard cert: %v", err), http.StatusBadRequest)
			return
		}
	}
	// generate a new uuid
	unew, err := uuid.NewV4()
	if err != nil {
		log.Printf("deviceAdd: error generating a new device UUID: %v", err)
		http.Error(w, fmt.Sprintf("error generating a new device UUID: %v", err), http.StatusBadRequest)
		return
	}
	if err := h.manager.DeviceRegister(unew, cert, onboard, t.Serial, common.CreateBaseConfig(unew)); err != nil {
		log.Printf("deviceAdd: DeviceRegister error: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *adminHandler) deviceList(w http.ResponseWriter, r *http.Request) {
	uids, err := h.manager.DeviceList()
	if err != nil {
		log.Printf("deviceList: DeviceList error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// convert the UUIDs
	ids := make([]string, 0, len(uids))
	for _, i := range uids {
		if i != nil {
			ids = append(ids, i.String())
		}
	}
	w.WriteHeader(http.StatusOK)
	body := strings.Join(ids, "\n")
	w.Header().Add(contentType, mimeTextPlain)
	w.Write([]byte(body))
}

func (h *adminHandler) deviceGet(w http.ResponseWriter, r *http.Request) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	deviceCert, onboardCert, serial, err := h.manager.DeviceGet(&uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("deviceGet: DeviceGet error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	case deviceCert == nil:
		http.Error(w, "found device information, but cert was empty", http.StatusInternalServerError)
	default:
		dc := DeviceCert{
			Cert:   ax.PemEncodeCert(deviceCert.Raw),
			Serial: serial,
		}
		if onboardCert != nil {
			dc.Onboard = ax.PemEncodeCert(onboardCert.Raw)
		}
		body, err := json.Marshal(dc)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}
}

func (h *adminHandler) deviceRemove(w http.ResponseWriter, r *http.Request) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	err = h.manager.DeviceRemove(&uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("deviceRemove: DeviceRemove error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (h *adminHandler) deviceClear(w http.ResponseWriter, r *http.Request) {
	err := h.manager.DeviceClear()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (h *adminHandler) deviceConfigGet(w http.ResponseWriter, r *http.Request) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	deviceConfig, err := h.manager.GetConfig(uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("deviceConfigGet: GetConfig error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	case deviceConfig == nil:
		http.Error(w, "found device information, but cert was empty", http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusOK)
		w.Write(deviceConfig)
	}
}

func (h *adminHandler) deviceConfigSet(w http.ResponseWriter, r *http.Request) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, "bad UUID", http.StatusBadRequest)
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("bad body: %v", err), http.StatusBadRequest)
		return
	}
	var deviceConfig config.EdgeDevConfig
	err = json.Unmarshal(body, &deviceConfig)
	if err != nil {
		log.Printf("deviceConfigSet: Unmarshal config error: %v", err)
		http.Error(w, fmt.Sprintf("failed to marshal json message into protobuf: %v", err), http.StatusBadRequest)
		return
	}
	// before setting the config, set any necessary defaults
	// check for UUID and/or version mismatch
	var (
		existingId     *config.UUIDandVersion
		existingConfig config.EdgeDevConfig
	)
	existingConfigB, err := h.manager.GetConfig(uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, fmt.Sprintf("device not found %s", u), http.StatusNotFound)
		return
	case err != nil:
		log.Printf("deviceConfigSet: GetConfig error: %v", err)
		http.Error(w, fmt.Sprintf("error retrieving existing config for device %s: %v", u, err), http.StatusBadRequest)
		return
	case len(existingConfigB) == 0:
		http.Error(w, "found device information, but had no config", http.StatusInternalServerError)
		return
	}
	// convert it to protobuf so we can work with it
	if err := protojson.Unmarshal(existingConfigB, &existingConfig); err != nil {
		log.Printf("deviceConfigSet: processing existing config error: %v", err)
		http.Error(w, fmt.Sprintf("error processing existing config: %v", err), http.StatusInternalServerError)
		return
	}
	existingId = existingConfig.Id

	// we only can bump the version if it is a valid integer
	newVersion, versionError := strconv.Atoi(existingId.Version)
	if versionError == nil {
		newVersion++
	}
	if deviceConfig.Id == nil {
		if versionError != nil {
			http.Error(w, fmt.Sprintf("cannot automatically non-number bump version %s", existingId.Version), http.StatusBadRequest)
			return
		}
		deviceConfig.Id = &config.UUIDandVersion{
			Uuid:    u,
			Version: strconv.Itoa(newVersion),
		}
	} else {
		if deviceConfig.Id.Uuid == "" {
			deviceConfig.Id.Uuid = u
		}
		if deviceConfig.Id.Version == "" {
			if versionError != nil {
				http.Error(w, fmt.Sprintf("cannot automatically non-number bump version %s", existingId.Version), http.StatusBadRequest)
				return
			}
			deviceConfig.Id.Version = strconv.Itoa(newVersion)
		}
		if deviceConfig.Id.Uuid != u {
			http.Error(w, fmt.Sprintf("mismatched UUID, setting %s for device %s", deviceConfig.Id.Uuid, u), http.StatusBadRequest)
			return
		}
	}

	b, err := protojson.Marshal(&deviceConfig)
	if err != nil {
		log.Printf("deviceConfigSet: Marshal error: %v", err)
		http.Error(w, fmt.Sprintf("error processing device config: %v", err), http.StatusBadRequest)
		return
	}
	err = h.manager.SetConfig(uid, b)
	_, isNotFound = err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("deviceConfigSet: SetConfig error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (h *adminHandler) deviceLogsGet(w http.ResponseWriter, r *http.Request) {
	h.deviceDataGet(w, r, h.logChannel, h.manager.GetLogsReader)
}

func (h *adminHandler) deviceInfoGet(w http.ResponseWriter, r *http.Request) {
	h.deviceDataGet(w, r, h.infoChannel, h.manager.GetInfoReader)
}

func (h *adminHandler) deviceRequestsGet(w http.ResponseWriter, r *http.Request) {
	h.deviceDataGet(w, r, h.requestsChannel, h.manager.GetRequestsReader)
}

func (h *adminHandler) deviceDataGet(w http.ResponseWriter, r *http.Request, c <-chan []byte, readerFunc func(u uuid.UUID) (io.Reader, error)) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	watch := r.Header.Get(StreamHeader)
	if watch == StreamValue {
		// get a close notifier so we can catch it and close ourselves
		cn, ok := w.(http.CloseNotifier)
		if !ok {
			http.NotFound(w, r)
			return
		}
		// get a flusher to send out data when streaming
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.NotFound(w, r)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-type", "application/json")
		flusher.Flush()

		for {
			select {
			case b := <-c:
				w.Write(append(b, 0x0a))
				flusher.Flush()
			case <-cn.CloseNotify():
				// client stopped listening
				return
			}
		}
	} else {
		reader, err := readerFunc(uid)
		_, isNotFound := err.(*common.NotFoundError)
		switch {
		case err != nil && isNotFound:
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		case err != nil:
			log.Printf("deviceDataGet: readerFunc error: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		case reader == nil:
			http.Error(w, "found device information, but logs were empty", http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-type", "application/json")
			_, err = io.Copy(w, reader)
			if err != nil && err != io.EOF {
				http.Error(w, fmt.Sprintf("error reading logs: %v", err), http.StatusInternalServerError)
			}
		}
	}
}

func (h *adminHandler) deviceCertsGet(w http.ResponseWriter, r *http.Request) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	deviceAttest, err := h.manager.GetCerts(uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		log.Printf("deviceCertsGet: %v", err)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("deviceCertsGet: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	case deviceAttest == nil:
		http.Error(w, "found device information, but certs was empty", http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusOK)
		w.Write(deviceAttest)
	}
}
