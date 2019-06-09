package server

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/satori/go.uuid"
	ax "github.com/zededa/adam/pkg/x509"
)

type adminHandler struct {
	manager DeviceManager
}

// OnboardCert encoding for sending an onboard cert and serials via json
type OnboardCert struct {
	Cert   []byte
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
	}
	decoder := json.NewDecoder(r.Body)
	var t OnboardCert
	err := decoder.Decode(&t)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}

	serials := strings.Split(t.Serial, ",")
	cert, err := ax.ParseCert(t.Cert)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
	err = h.manager.OnboardRegister(cert, serials)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *adminHandler) onboardList(w http.ResponseWriter, r *http.Request) {
	cns, err := h.manager.OnboardList()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
	w.WriteHeader(http.StatusOK)
	body := strings.Join(cns, "\n")
	w.Header().Add(contentType, mimeTextPlain)
	w.Write([]byte(body))
}

func (h *adminHandler) onboardGet(w http.ResponseWriter, r *http.Request) {
	cn := mux.Vars(r)["cn"]
	cert, serials, err := h.manager.OnboardGet(cn)
	_, isNotFound := err.(*NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusOK)
		body, err := json.Marshal(OnboardCert{
			Cert:   ax.PemEncodeCert(cert.Raw),
			Serial: strings.Join(serials, ","),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		w.Write([]byte(body))
	}
}

func (h *adminHandler) onboardRemove(w http.ResponseWriter, r *http.Request) {
	cn := mux.Vars(r)["cn"]
	err := h.manager.OnboardRemove(cn)
	_, isNotFound := err.(*NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (h *adminHandler) onboardClear(w http.ResponseWriter, r *http.Request) {
	err := h.manager.OnboardClear()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (h *adminHandler) deviceAdd(w http.ResponseWriter, r *http.Request) {
	// extract certificate and serials from request body
	contentType := r.Header.Get(contentType)
	if contentType != mimeTextPlain {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}

	decoder := json.NewDecoder(r.Body)
	var (
		t       DeviceCert
		cert    *x509.Certificate
		onboard *x509.Certificate
	)
	err := decoder.Decode(&t)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}

	cert, err = ax.ParseCert(t.Cert)
	if err != nil {
		http.Error(w, fmt.Sprintf("bad device cert: %v", err), http.StatusBadRequest)
	}
	if t.Onboard != nil && len(t.Onboard) > 0 {
		onboard, err = ax.ParseCert(t.Onboard)
		if err != nil {
			http.Error(w, fmt.Sprintf("bad onboard cert: %v", err), http.StatusBadRequest)
		}
	}
	_, err = h.manager.DeviceRegister(cert, onboard, t.Serial)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *adminHandler) deviceList(w http.ResponseWriter, r *http.Request) {
	uids, err := h.manager.DeviceList()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
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
	_, isNotFound := err.(*NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
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
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
	_, isNotFound := err.(*NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
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
	_, isNotFound := err.(*NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	case deviceConfig == nil:
		http.Error(w, "found device information, but cert was empty", http.StatusInternalServerError)
	default:
		body, err := json.Marshal(deviceConfig)
		if err != nil {
			http.Error(w, fmt.Sprintf("error marshaling config to json: %v", err), http.StatusInternalServerError)
		}
		w.WriteHeader(http.StatusOK)
		w.Write(body)
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
	}
	var deviceConfig config.EdgeDevConfig
	err = json.Unmarshal(body, &deviceConfig)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal json message into protobuf: %v", err), http.StatusBadRequest)
	}
	err = h.manager.SetConfig(uid, &deviceConfig)
	_, isNotFound := err.(*NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusOK)
	}
}
