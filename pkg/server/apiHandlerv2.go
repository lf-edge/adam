// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/gorilla/mux"
	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/adam/pkg/driver/common"
	x509Pem "github.com/lf-edge/adam/pkg/x509"
	"github.com/lf-edge/eve/api/go/auth"
	"github.com/lf-edge/eve/api/go/certs"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/evecommon"
	uuid "github.com/satori/go.uuid"
)

type apiHandlerv2 struct {
	manager         driver.DeviceManager
	logChannel      chan []byte
	infoChannel     chan []byte
	metricChannel   chan []byte
	signingCertPath string
	signingKeyPath  string
	encryptCertPath string
	encryptKeyPath  string
}

const (
	nonce          = "dummy_nonce"
	integrityToken = "dummy_integrity_token"
)

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

//getAllCerts process certificates files and return structure with them
func (h *apiHandlerv2) getAllCerts() (map[string]*certs.ZCert, error) {
	allCerts := make(map[string]*certs.ZCert)
	signingCerts, sgErr := getCertChain(h.signingCertPath, certs.ZCertType_CERT_TYPE_CONTROLLER_SIGNING)
	if sgErr != nil {
		return nil, fmt.Errorf("error occurred while fetching signing cert chain: %v", sgErr)
	}

	//fill signing and intermediate certificate in map structure.
	for _, cert := range signingCerts.Certs {
		allCerts[string(cert.CertHash)] = cert
	}

	encryptCerts, egErr := getCertChain(h.encryptCertPath, certs.ZCertType_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE)
	if egErr != nil {
		return nil, fmt.Errorf("error occurred while fetching encryption cert chain: %v", egErr)
	}

	//fill encryption and intermediate certificate in map structure.
	for _, cert := range encryptCerts.Certs {
		allCerts[string(cert.CertHash)] = cert
	}

	return allCerts, nil
}

func getCertChain(certPath string, certType certs.ZCertType) (*common.Zcerts, error) {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, err
	}

	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	var certContent []*certs.ZCert
	//split certificates from file.
	certsArr := strings.SplitAfter(string(certData), "-----END CERTIFICATE-----")
	for _, cert := range certsArr {
		certsAfterTrim := strings.TrimSpace(cert)
		if len(certsAfterTrim) == 0 {
			continue
		}
		individualCert := []byte(certsAfterTrim)
		shaOfCert := sha256.Sum256(individualCert)

		certDetail := &certs.ZCert{}
		certDetail.Cert = individualCert
		certDetail.CertHash = shaOfCert[:]

		parsedCert, pErr := x509Pem.ParseCertFromBlock(individualCert)
		if pErr != nil {
			return nil, pErr
		}
		for _, pVal := range parsedCert {
			if !pVal.IsCA {
				certDetail.Type = certType
			} else {
				certDetail.Type = certs.ZCertType_CERT_TYPE_CONTROLLER_INTERMEDIATE
			}
		}
		certContent = append(certContent, certDetail)
	}
	zcerts := &common.Zcerts{
		Certs: certContent,
	}
	return zcerts, nil
}

func (h *apiHandlerv2) certs(w http.ResponseWriter, r *http.Request) {

	//read trust certificate
	certsSlice, gErr := h.getAllCerts()
	if gErr != nil {
		msg := fmt.Sprintf("Error occurred while fetching zcerts: %v", gErr)
		log.Print(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	var eveCerts []*certs.ZCert
	for _, cert := range certsSlice {
		certDetail := &certs.ZCert{}
		certDetail.HashAlgo = evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES
		certDetail.CertHash = cert.CertHash[:16]
		certDetail.Type = cert.Type
		certDetail.Cert = cert.Cert
		eveCerts = append(eveCerts, certDetail)
	}
	ctrlCert := &certs.ZControllerCert{
		Certs: eveCerts,
	}
	certByte, err := proto.Marshal(ctrlCert)
	if err != nil {
		msg := fmt.Sprintf("error marshal ZControllerCert: %v", err)
		log.Print(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	cloudEnvelope, eErr := h.prepareEnvelope(certByte)
	if eErr != nil {
		msg := fmt.Sprintf("Error occurred while creating envelope: %v", eErr)
		log.Print(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	w.Header().Set(contentType, mimeProto)
	w.WriteHeader(http.StatusOK)
	w.Write(cloudEnvelope)
}

func ecdsakeyBytes(pubKey *ecdsa.PublicKey) (int, error) {
	curveBits := pubKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	if keyBytes%8 > 0 {
		return 0, fmt.Errorf("ecdsa pubkey size error, curveBits %v", curveBits)
	}
	return keyBytes, nil
}

func rsCombinedBytes(rBytes, sBytes []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	keySize, err := ecdsakeyBytes(pubKey)
	if err != nil {
		return nil, fmt.Errorf("RSCombinedBytes: ecdsa key bytes error %v", err)
	}
	rsize := len(rBytes)
	ssize := len(sBytes)
	if rsize > keySize || ssize > keySize {
		return nil, fmt.Errorf("RSCombinedBytes: error. keySize %v, rSize %v, sSize %v", keySize, rsize, ssize)
	}

	// basically the size is 32 bytes. the r and s needs to be both left padded to two 32 bytes slice
	// into a single signature buffer
	buffer := make([]byte, keySize*2)
	startPos := keySize - rsize
	copy(buffer[startPos:], rBytes)
	startPos = keySize*2 - ssize
	copy(buffer[startPos:], sBytes)
	return buffer[:], nil
}

func computeSignatureWithCertAndKey(shaOfPayload, certPem, keyPem []byte) ([]byte, error) {
	var signature []byte
	var rsCombErr error

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, fmt.Errorf("computeSignatureWithCertAndKey X509KeyPair: %v", err)
	}
	switch key := cert.PrivateKey.(type) {

	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, shaOfPayload)
		if err != nil {
			return nil, err
		}
		signature, rsCombErr = rsCombinedBytes(r.Bytes(), s.Bytes(), &key.PublicKey)
		if rsCombErr != nil {
			return nil, rsCombErr
		}

	case *rsa.PrivateKey:
		var sErr error
		signature, sErr = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, shaOfPayload)
		if sErr != nil {
			return nil, sErr
		}
	default:
		return nil, fmt.Errorf("signAuthData: privatekey default")

	}
	return signature, nil
}

func (h *apiHandlerv2) prepareEnvelope(payload []byte) ([]byte, error) {
	zcloudMsg := &auth.AuthContainer{}

	//get sender cert detail
	var senderCertHash []byte
	var signingCert []byte

	zcerts, gErr := getCertChain(h.signingCertPath, certs.ZCertType_CERT_TYPE_CONTROLLER_SIGNING)
	if gErr != nil {
		return nil, gErr
	}
	for _, cert := range zcerts.Certs {
		if cert.Type == certs.ZCertType_CERT_TYPE_CONTROLLER_SIGNING {
			senderCertHash = cert.CertHash
			signingCert = cert.Cert
		}
	}

	//read private signing key.
	signingPrivateKey, rErr := ioutil.ReadFile(h.signingKeyPath)
	if rErr != nil {
		return nil, fmt.Errorf("error occurred while reading signing key: %v", rErr)
	}

	//compute hash of payload
	hashedPayload := sha256.Sum256(payload)

	//compute signature of payload hash
	signatureOfPayloadHash, scErr := computeSignatureWithCertAndKey(hashedPayload[:], signingCert, signingPrivateKey)
	if scErr != nil {
		return nil, fmt.Errorf("error occurred while computing signature: %v", scErr)
	}

	authBody := new(auth.AuthBody)
	authBody.Payload = payload
	zcloudMsg.ProtectedPayload = authBody
	zcloudMsg.Algo = evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_32BYTES
	zcloudMsg.SenderCertHash = senderCertHash
	zcloudMsg.SignatureHash = signatureOfPayloadHash

	return proto.Marshal(zcloudMsg)
}

func (h *apiHandlerv2) register(w http.ResponseWriter, r *http.Request) {
	// get the onboard cert and unpack the message to:
	//  - get the serial
	//  - get the device cert
	onboardCert := getClientCert(r)
	b, err := h.processAuthContainer(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error processAuthContainer: %v", err)
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
	data, code, err := configProcess(configRequest, cfg)
	if err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(code), code)
		return
	}
	if code == http.StatusNotModified {
		w.WriteHeader(code)
		return
	}
	cloudEnvelope, eErr := h.prepareEnvelope(data)
	if eErr != nil {
		msg := fmt.Sprintf("Error occurred while creating envelope: %v", eErr)
		log.Print(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	w.Header().Set(contentType, mimeProto)
	w.WriteHeader(http.StatusOK)
	w.Write(cloudEnvelope)
}

func (h *apiHandlerv2) config(w http.ResponseWriter, r *http.Request) {
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
	cloudEnvelope, eErr := h.prepareEnvelope(cfg)
	if eErr != nil {
		msg := fmt.Sprintf("Error occurred while creating envelope: %v", eErr)
		log.Print(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	w.Header().Set(contentType, mimeProto)
	w.WriteHeader(http.StatusOK)
	w.Write(cloudEnvelope)
}

func (h *apiHandlerv2) processAuthContainer(reader io.Reader) ([]byte, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("error reading request body: %v", err)
	}
	sm := &auth.AuthContainer{}
	if err := proto.Unmarshal(b, sm); err != nil {
		return nil, fmt.Errorf("error reading request body: %v", err)
	}
	return sm.ProtectedPayload.GetPayload(), nil
}

func (h *apiHandlerv2) attest(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	b, err := h.processAuthContainer(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error processAuthContainer: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	out, status, err := attestProcess(h.manager, *u, b)
	if err != nil {
		log.Printf("Failed to attestProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	cloudEnvelope, eErr := h.prepareEnvelope(out)
	if eErr != nil {
		msg := fmt.Sprintf("Error occurred while creating envelope: %v", eErr)
		log.Print(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	w.Header().Set(contentType, mimeProto)
	w.WriteHeader(http.StatusCreated)
	w.Write(cloudEnvelope)
}

func (h *apiHandlerv2) info(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	b, err := h.processAuthContainer(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error processAuthContainer: %v", err)
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

func (h *apiHandlerv2) metrics(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	b, err := h.processAuthContainer(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error processAuthContainer: %v", err)
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

func (h *apiHandlerv2) logs(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	b, err := h.processAuthContainer(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error processAuthContainer: %v", err)
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

func (h *apiHandlerv2) newLogs(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	b, err := h.processAuthContainer(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error processAuthContainer: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	status, err := newLogsProcess(h.manager, h.logChannel, *u, bytes.NewReader(b))
	if err != nil {
		log.Printf("Failed to logsProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

func (h *apiHandlerv2) appLogs(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	uid, err := uuid.FromString(mux.Vars(r)["appuuid"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	b, err := h.processAuthContainer(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error processAuthContainer: %v", err)
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

func (h *apiHandlerv2) newAppLogs(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	uid, err := uuid.FromString(mux.Vars(r)["appuuid"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	b, err := h.processAuthContainer(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error processAuthContainer: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	status, err := newAppLogsProcess(h.manager, *u, uid, bytes.NewReader(b))
	if err != nil {
		log.Printf("Failed to logsProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

// retrieve the config request
func (h *apiHandlerv2) getClientConfigRequest(r *http.Request) (*config.ConfigRequest, error) {
	b, err := h.processAuthContainer(r.Body)
	if err != nil {
		return nil, fmt.Errorf("error processAuthContainer: %v", err)
	}
	if len(b) == 0 {
		return nil, nil
	}
	body, err := ioutil.ReadAll(bytes.NewReader(b))
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

func (h *apiHandlerv2) flowlog(w http.ResponseWriter, r *http.Request) {
	u := h.checkCertAndRecord(w, r)
	if u == nil {
		return
	}
	b, err := h.processAuthContainer(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error processAuthContainer: %v", err)
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
