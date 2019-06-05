package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/satori/go.uuid"
	ax "github.com/zededa/adam/pkg/x509"
)

type adminHandler struct {
	manager DeviceManager
}

func (h *adminHandler) onboardAdd(w http.ResponseWriter, r *http.Request) {
}

func (h *adminHandler) onboardList(w http.ResponseWriter, r *http.Request) {
	cns, err := h.manager.ListOnboard()
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
	cert, serials, err := h.manager.GetOnboard(cn)
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
	err := h.manager.RemoveOnboard(cn)
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
}

func (h *adminHandler) deviceAdd(w http.ResponseWriter, r *http.Request) {
}

func (h *adminHandler) deviceList(w http.ResponseWriter, r *http.Request) {
	uids, err := h.manager.ListDevice()
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
	deviceCert, onboardCert, serial, err := h.manager.GetDevice(&uid)
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
	err = h.manager.RemoveDevice(&uid)
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
}
