// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"compress/gzip"
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
	"github.com/lf-edge/eve/api/go/auth"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type ApiRequestv2 struct {
	Timestamp time.Time `json:"timestamp"`
	UUID      uuid.UUID `json:"uuid,omitempty"`
	ClientIP  string    `json:"client-ip"`
	Forwarded string    `json:"forwarded,omitempty"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
}

type apiHandlerv2 struct {
	manager     driver.DeviceManager
	logChannel  chan []byte
	infoChannel chan []byte
}

// GetUser godoc
// @Summary Retrieves user based on given ID
// @Produce json
// @Param id path integer true "User ID"
// @Success 200 {object} models.User
// @Router /users/{id} [get]
func (h *apiHandlerv2) recordClient(u *uuid.UUID, r *http.Request) {
	if u == nil {
		// we ignore non-device-specific requests for now
		log.Printf("error saving request for device without UUID")
		return
	}
	req := ApiRequestv2{
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

func (h *apiHandlerv2) checkCertAndRecord(w http.ResponseWriter, r *http.Request) *uuid.UUID {
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

func verifyAuthentication(ctx *ZedCloudContext, c []byte, skipVerify bool) ([]byte, types.SenderResult, error) {
	senderSt := types.SenderStatusNone
	sm := &zauth.AuthContainer{}
	err := proto.Unmarshal(c, sm)
	if err != nil {
		ctx.log.Errorf("verifyAuthentication: can not unmarshal authen content, %v\n", err)
		return nil, senderSt, err
	}

	data := sm.ProtectedPayload.GetPayload()
	if !skipVerify { // no verify for /certs itself
		if len(sm.GetSenderCertHash()) != hashSha256Len16 &&
			len(sm.GetSenderCertHash()) != hashSha256Len32 {
			ctx.log.Errorf("verifyAuthentication: senderCertHash length %d\n",
				len(sm.GetSenderCertHash()))
			err := fmt.Errorf("verifyAuthentication: senderCertHash length error")
			return nil, types.SenderStatusHashSizeError, err
		}

		if ctx.serverSigningCert == nil {
			err := getServerSigingCert(ctx)
			if err != nil {
				ctx.log.Errorf("verifyAuthentication: can not get server cert, %v\n", err)
				return nil, senderSt, err
			}
		}

		switch sm.Algo {
		case zcommon.HashAlgorithm_HASH_ALGORITHM_SHA256_32BYTES:
			if bytes.Compare(sm.GetSenderCertHash(), ctx.serverSigningCertHash) != 0 {
				err := fmt.Errorf("verifyAuthentication: local server cert hash 32bytes does not match in authen")
				ctx.log.Errorf("verifyAuthentication: local server cert hash(%d) does not match in authen (%d) %v, %v",
					len(ctx.serverSigningCertHash), len(sm.GetSenderCertHash()), ctx.serverSigningCertHash, sm.GetSenderCertHash())
				return nil, types.SenderStatusCertMiss, err
			}
		case zcommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES:
			if bytes.Compare(sm.GetSenderCertHash(), ctx.serverSigningCertHash[:hashSha256Len16]) != 0 {
				err := fmt.Errorf("verifyAuthentication: local server cert hash 16bytes does not match in authen")
				ctx.log.Errorf("verifyAuthentication: local server cert hash(%d) does not match in authen (%d) %v, %v",
					len(ctx.serverSigningCertHash), len(sm.GetSenderCertHash()), ctx.serverSigningCertHash, sm.GetSenderCertHash())
				return nil, types.SenderStatusCertMiss, err
			}
		default:
			ctx.log.Errorf("verifyAuthentication: hash algorithm is not supported\n")
			err := fmt.Errorf("verifyAuthentication: hash algorithm is not supported")
			return nil, types.SenderStatusAlgoFail, err
		}

		hash := ComputeSha(data)
		err = verifyAuthSig(ctx, sm.GetSignatureHash(), ctx.serverSigningCert, hash)
		if err != nil {
			ctx.log.Errorf("verifyAuthentication: verifyAuthSig error %v\n", err)
			return nil, types.SenderStatusSignVerifyFail, err
		}
		ctx.log.Tracef("verifyAuthentication: ok\n")
	}
	return data, senderSt, nil
}


func (h *apiHandlerv2) register(w http.ResponseWriter, r *http.Request) {
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

func (h *apiHandlerv2) probe(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s requested probe", r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
}

func (h *apiHandlerv2) ping(w http.ResponseWriter, r *http.Request) {
	if devID := h.checkCertAndRecord(w, r); devID == nil {
		return
	}
	// now just return a 200
	w.WriteHeader(http.StatusOK)
}

func (h *apiHandlerv2) configPost(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
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

func (h *apiHandlerv2) config(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	config, err := h.manager.GetConfig(*u)
	if err != nil {
		log.Printf("error getting device config: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	
	w.Header().Add(contentType, mimeProto)
	w.WriteHeader(http.StatusOK)
	w.Write(config)
}

func (h *apiHandlerv2) info(w http.ResponseWriter, r *http.Request) {
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
	msg := &info.ZInfoMsg{}
	if err := proto.Unmarshal(b, msg); err != nil {
		log.Printf("Failed to parse info message: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	var entryBytes []byte
	if entryBytes, err = protojson.Marshal(msg); err != nil {
		log.Printf("Failed to marshal info message: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	select {
	case h.infoChannel <- entryBytes:
	default:
	}
	err = h.manager.WriteInfo(*u, entryBytes)
	if err != nil {
		log.Printf("Failed to write info message: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// send back a 201
	w.WriteHeader(http.StatusCreated)
}

func (h *apiHandlerv2) metrics(w http.ResponseWriter, r *http.Request) {
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
	msg := &metrics.ZMetricMsg{}
	if err := proto.Unmarshal(b, msg); err != nil {
		log.Printf("Failed to parse metrics message: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	var entryBytes []byte
	if entryBytes, err = protojson.Marshal(msg); err != nil {
		log.Printf("Failed to marshal metrics message: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	err = h.manager.WriteMetrics(*u, entryBytes)
	if err != nil {
		log.Printf("Failed to write metrics message: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// send back a 201
	w.WriteHeader(http.StatusCreated)
}

func (h *apiHandlerv2) logs(w http.ResponseWriter, r *http.Request) {
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
	msg := &logs.LogBundle{}
	if err := proto.Unmarshal(b, msg); err != nil {
		log.Printf("Failed to parse logbundle message: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	eveVersion := msg.GetEveVersion()
	image := msg.GetImage()
	for _, entry := range msg.GetLog() {
		entry := &common.FullLogEntry{
			LogEntry:   entry,
			Image:      image,
			EveVersion: eveVersion,
		}
		var entryBytes []byte
		if entryBytes, err = entry.Json(); err != nil {
			log.Printf("Failed to marshal FullLogEntry message: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		select {
		case h.logChannel <- entryBytes:
		default:
		}
		err = h.manager.WriteLogs(*u, entryBytes)
		if err != nil {
			log.Printf("Failed to write log message: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	// send back a 201
	w.WriteHeader(http.StatusCreated)
}

func (h *apiHandlerv2) newLogs(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	gr, err := gzip.NewReader(r.Body)
	if err != nil {
		log.Printf("error gzip.NewReader: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	msg := &logs.LogBundle{}
	if err := json.Unmarshal([]byte(gr.Comment), msg); err != nil {
		log.Printf("Failed to parse logbundle from Comment: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	scanner := bufio.NewScanner(gr)
	for scanner.Scan() {
		le := &logs.LogEntry{}
		if err := json.Unmarshal(scanner.Bytes(), le); err != nil {
			log.Printf("Failed to parse logentry message: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		entry := &common.FullLogEntry{
			LogEntry:   le,
			Image:      msg.GetImage(),
			EveVersion: msg.GetEveVersion(),
		}
		var entryBytes []byte
		if entryBytes, err = entry.Json(); err != nil {
			log.Printf("Failed to marshal FullLogEntry message: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		select {
		case h.logChannel <- entryBytes:
		default:
		}
		err = h.manager.WriteLogs(*u, entryBytes)
		if err != nil {
			log.Printf("Failed to write logbundle message: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *apiHandlerv2) appLogs(w http.ResponseWriter, r *http.Request) {
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
	msg := &logs.AppInstanceLogBundle{}
	if err := proto.Unmarshal(b, msg); err != nil {
		log.Printf("Failed to parse appinstancelogbundle message: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	for _, le := range msg.Log {
		var b []byte
		if b, err = protojson.Marshal(le); err != nil {
			log.Printf("Failed to marshal LogEntry message: %v", err)
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
	}
	// send back a 201
	w.WriteHeader(http.StatusCreated)
}

func (h *apiHandlerv2) newAppLogs(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	uid, err := uuid.FromString(mux.Vars(r)["uuid"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	gr, err := gzip.NewReader(r.Body)
	if err != nil {
		log.Printf("error gzip.NewReader: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	scanner := bufio.NewScanner(gr)
	for scanner.Scan() {
		le := &logs.LogEntry{}
		if err := json.Unmarshal(scanner.Bytes(), le); err != nil {
			log.Printf("Failed to parse logentry message: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		var b []byte
		if b, err = protojson.Marshal(le); err != nil {
			log.Printf("Failed to marshal LogEntry message: %v", err)
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
	}
	// send back a 201
	w.WriteHeader(http.StatusCreated)
}
