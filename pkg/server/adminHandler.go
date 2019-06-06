package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/satori/go.uuid"
	ax "github.com/zededa/adam/pkg/x509"
)

type adminHandler struct {
	manager DeviceManager
}

type onboardCert struct {
	Cert   []byte
	Serial string
}

func (h *adminHandler) onboardAdd(w http.ResponseWriter, r *http.Request) {
	// extract certificate and serials from request body
	contentType := r.Header.Get(contentType)
	if contentType != mimeJSON {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
	decoder := json.NewDecoder(r.Body)
	var t onboardCert
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
		body := fmt.Sprintf(`{"cert":"%s", "serials":"%s"}`, string(ax.PemEncodeCert(cert.Raw)), strings.Join(serials, ","))
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

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}

	cert, err := ax.ParseCert(b)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
	_, err = h.manager.DeviceRegister(cert, nil, "")
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
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	deviceCert, onboardCert, serial, err := h.manager.DeviceGet(&uid)
	_, isNotFound := err.(*NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusOK)
		body := fmt.Sprintf(`{"cert":"%s", "onboard": "%s", "serial":"%s"}`, string(ax.PemEncodeCert(deviceCert.Raw)), string(ax.PemEncodeCert(onboardCert.Raw)), serial)
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
