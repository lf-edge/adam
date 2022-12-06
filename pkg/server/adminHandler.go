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

	"github.com/aohorodnyk/mimeheader"
	"github.com/gorilla/mux"
	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/adam/pkg/driver/common"
	ax "github.com/lf-edge/adam/pkg/x509"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/info"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
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
		ah := mimeheader.ParseAcceptHeader(r.Header.Get(accept))
		// if Accept header match mime application/json or not match application/x-proto-binary do conversion to JSON
		if ah.Match(mimeJSON) || !ah.Match(mimeProto) {
			var deviceConfigObj config.EdgeDevConfig
			err = proto.Unmarshal(deviceConfig, &deviceConfigObj)
			if err != nil {
				log.Printf("deviceConfigGet: Unmarshal error: %v", err)
				http.Error(w, "cannot unmarshal stored EdgeDevConfig", http.StatusInternalServerError)
				return
			}
			deviceConfig, err = protojson.Marshal(&deviceConfigObj)
			if err != nil {
				log.Printf("deviceConfigGet: Marshal error: %v", err)
				http.Error(w, "cannot marshal stored EdgeDevConfig", http.StatusInternalServerError)
				return
			}
		}
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
	switch r.Header.Get(contentType) {
	case mimeProto:
		err = proto.Unmarshal(body, &deviceConfig)
	case mimeJSON:
		fallthrough
	default:
		err = json.Unmarshal(body, &deviceConfig)
	}
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
	if err := proto.Unmarshal(existingConfigB, &existingConfig); err != nil {
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

	b, err := proto.Marshal(&deviceConfig)
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
	h.deviceDataGet(w, r, h.logChannel, h.manager.GetLogsReader, nil)
}

func (h *adminHandler) deviceInfoGet(w http.ResponseWriter, r *http.Request) {
	h.deviceDataGet(w, r, h.infoChannel, h.manager.GetInfoReader, func(in []byte) ([]byte, error) {
		var err error
		msg := &info.ZInfoMsg{}
		if err = proto.Unmarshal(in, msg); err != nil {
			return nil, fmt.Errorf("error parsing info message: %v", err)
		}
		var entryBytes []byte
		if entryBytes, err = protojson.Marshal(msg); err != nil {
			return nil, fmt.Errorf("failed to marshal info message: %v", err)
		}
		return entryBytes, nil
	})
}

func (h *adminHandler) deviceRequestsGet(w http.ResponseWriter, r *http.Request) {
	h.deviceDataGet(w, r, h.requestsChannel, h.manager.GetRequestsReader, nil)
}

func (h *adminHandler) deviceDataGet(w http.ResponseWriter, r *http.Request, c <-chan []byte, readerFunc func(u uuid.UUID) (common.ChunkReader, error), conversionFunc func(in []byte) ([]byte, error)) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	conversionRequired := false
	if conversionFunc != nil {
		ah := mimeheader.ParseAcceptHeader(r.Header.Get(accept))
		// if Accept header match mime application/json or not match application/x-proto-binary do conversion to JSON
		if ah.Match(mimeJSON) || !ah.Match(mimeProto) {
			conversionRequired = true
		}
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
				if conversionRequired {
					b, err = conversionFunc(b)
					if err != nil {
						log.Printf("conversionFunc failed: %v", err)
						continue
					}
				}
				w.Write(append(b, 0x0a))
				flusher.Flush()
			case <-cn.CloseNotify():
				// client stopped listening
				return
			}
		}
	} else {
		for {
			chunk, err := readerFunc(uid)
			_, isNotFound := err.(*common.NotFoundError)
			switch {
			case err != nil && isNotFound:
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			case err != nil:
				log.Printf("deviceDataGet: readerFunc error: %v", err)
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			default:
				w.WriteHeader(http.StatusOK)
				w.Header().Set("Content-type", "application/json")
				for {
					reader, size, err := chunk.NextChunkReader()
					if reader == nil {
						return
					}
					if err != nil && err != io.EOF {
						http.Error(w, fmt.Sprintf("error reading chunkSize: %v", err), http.StatusInternalServerError)
						continue
					}
					buf := make([]byte, size)
					_, err = io.ReadFull(reader, buf)
					if err != nil && err != io.EOF {
						http.Error(w, fmt.Sprintf("error reading data: %v", err), http.StatusInternalServerError)
						continue
					}
					if conversionRequired {
						buf, err = conversionFunc(buf)
						if err != nil {
							log.Printf("conversionFunc failed: %v", err)
							continue
						}
					}
					w.Write(append(buf, 0x0a))
				}
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

func (h *adminHandler) deviceOptionsGet(w http.ResponseWriter, r *http.Request) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	deviceOptions, err := h.manager.GetDeviceOptions(uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		log.Printf("deviceOptionsGet: %v", err)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("deviceOptionsGet: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	case deviceOptions == nil:
		http.Error(w, "found device information, but options was empty", http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusOK)
		w.Write(deviceOptions)
	}
}

func (h *adminHandler) deviceOptionsSet(w http.ResponseWriter, r *http.Request) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("bad body: %v", err), http.StatusBadRequest)
		return
	}
	var deviceOptions common.DeviceOptions
	err = json.Unmarshal(body, &deviceOptions)
	if err != nil {
		log.Printf("deviceOptionsSet: Unmarshal options error: %v", err)
		http.Error(w, fmt.Sprintf("failed to marshal json message into protobuf: %v", err), http.StatusBadRequest)
		return
	}
	err = h.manager.SetDeviceOptions(uid, body)
	if err != nil {
		log.Printf("deviceOptionsSet: %s", err)
		http.Error(w, fmt.Sprintf("failed to set device options: %s", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *adminHandler) globalOptionsGet(w http.ResponseWriter, _ *http.Request) {
	globalOptions, err := h.manager.GetGlobalOptions()
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		log.Printf("globalOptionsGet: %v", err)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("globalOptionsGet: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	case globalOptions == nil:
		http.Error(w, "found information, but options was empty", http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusOK)
		w.Write(globalOptions)
	}
}

func (h *adminHandler) globalOptionsSet(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("bad body: %v", err), http.StatusBadRequest)
		return
	}
	var globalOptions common.GlobalOptions
	err = json.Unmarshal(body, &globalOptions)
	if err != nil {
		log.Printf("globalOptionsSet: Unmarshal options error: %v", err)
		http.Error(w, fmt.Sprintf("failed to marshal json message into protobuf: %v", err), http.StatusBadRequest)
		return
	}
	err = h.manager.SetGlobalOptions(body)
	if err != nil {
		log.Printf("globalOptionsSet: %s", err)
		http.Error(w, fmt.Sprintf("failed to set global options: %s", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
