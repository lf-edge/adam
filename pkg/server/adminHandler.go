package server

import (
	"net/http"
)

type adminHandler struct {
	manager DeviceManager
}

func (h *adminHandler) onboardAdd(w http.ResponseWriter, r *http.Request) {
}

func (h *adminHandler) onboardList(w http.ResponseWriter, r *http.Request) {
}

func (h *adminHandler) onboardGet(w http.ResponseWriter, r *http.Request) {
}

func (h *adminHandler) onboardRemove(w http.ResponseWriter, r *http.Request) {
}

func (h *adminHandler) onboardClear(w http.ResponseWriter, r *http.Request) {
}

func (h *adminHandler) deviceAdd(w http.ResponseWriter, r *http.Request) {
}

func (h *adminHandler) deviceList(w http.ResponseWriter, r *http.Request) {
}

func (h *adminHandler) deviceGet(w http.ResponseWriter, r *http.Request) {
}

func (h *adminHandler) deviceRemove(w http.ResponseWriter, r *http.Request) {
}

func (h *adminHandler) deviceClear(w http.ResponseWriter, r *http.Request) {
}
