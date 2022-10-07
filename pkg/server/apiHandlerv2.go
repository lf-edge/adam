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
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
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
	eveuuid "github.com/lf-edge/eve/api/go/eveuuid"
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
	protoFormat     bool
}

func (h *apiHandlerv2) Manager() driver.DeviceManager {
	return h.manager
}

func (h *apiHandlerv2) ProtoFormat() bool {
	return h.protoFormat
}

const (
	nonceSize          = 12
	integrityTokenSize = 128
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

//validateAuthContainerAndRecord processes http.Request extracts AuthContainer and do its validation
//against registered devices:
// checks for certs hash in AuthContainer and go through saved certs to check auth state
// it verifies Signature of AuthContainer payload against saved cert
// returns ProtectedPayload and device uuid
func (h *apiHandlerv2) validateAuthContainerAndRecord(w http.ResponseWriter, r *http.Request) ([]byte, *uuid.UUID) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil || len(b) == 0 {
		log.Printf("error reading request body: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil, nil
	}
	sm := &auth.AuthContainer{}
	if err := proto.Unmarshal(b, sm); err != nil {
		log.Printf("error reading request body: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil, nil
	}
	if len(sm.SenderCertHash) == 0 {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return nil, nil
	}
	u, err := h.manager.DeviceCheckCertHash(sm.SenderCertHash)
	if err != nil {
		log.Printf("error checking DeviceCheckCertHash: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return nil, nil
	}
	devCert, _, _, err := h.manager.DeviceGet(u)
	if err != nil {
		log.Printf("error getting DeviceCerts: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return nil, nil
	}
	payload := sm.ProtectedPayload.GetPayload()
	hashedPayload := sha256.Sum256(payload)
	// validate signature with the certificate.
	svErr := verifySignature(sm.SignatureHash, hashedPayload[:], devCert)
	if svErr != nil {
		log.Printf("signature verification failed: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return nil, nil
	}
	h.recordClient(u, r)
	return payload, u
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

func verifySignature(signature, payloadHash []byte, cert *x509.Certificate) error {

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, payloadHash, signature)
		if err != nil {
			return fmt.Errorf("rsa signature verification failed: %s", err)
		}

	case *ecdsa.PublicKey:

		sigHalfLen, err := ecdsakeyBytes(pub)
		if err != nil {
			return err
		}

		rbytes := signature[0:sigHalfLen]
		sbytes := signature[sigHalfLen:]
		r := new(big.Int)
		s := new(big.Int)
		r.SetBytes(rbytes)
		s.SetBytes(sbytes)

		var esig struct {
			R, S *big.Int
		}

		_, uErr := asn1.Unmarshal(signature, &esig)
		if uErr != nil {
			ok := ecdsa.Verify(pub, payloadHash, r, s)
			if !ok {
				return fmt.Errorf("ecdsa signature verification failed")
			}
		} else {
			ok := ecdsa.Verify(pub, payloadHash, esig.R, esig.S)
			if !ok {
				return fmt.Errorf("ecdsa signature verification failed")
			}
		}
	default:
		return fmt.Errorf("unknown type of public key")
	}
	return nil
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

func (h *apiHandlerv2) processAuthContainer(reader io.Reader) (*auth.AuthContainer, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("error reading request body: %v", err)
	}
	sm := &auth.AuthContainer{}
	if err := proto.Unmarshal(b, sm); err != nil {
		return nil, fmt.Errorf("error unmarshal AuthContainer: %v", err)
	}
	return sm, nil
}

func (h *apiHandlerv2) register(w http.ResponseWriter, r *http.Request) {
	// get the onboard cert and unpack the message to:
	//  - get the serial
	//  - get the device cert
	b, err := h.processAuthContainer(r.Body)
	if err != nil || b.ProtectedPayload == nil || len(b.ProtectedPayload.GetPayload()) == 0 {
		log.Printf("error processAuthContainer: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	onBoardCertDecoded, err := base64.StdEncoding.DecodeString(string(b.GetSenderCert()))
	if err != nil {
		log.Printf("error decoding SenderCert: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	onboardCert, err := x509Pem.ParseCertFromBlock(onBoardCertDecoded)
	if err != nil {
		log.Printf("error parsing SenderCert: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if len(onboardCert) == 0 {
		log.Println("no certificates parsed from SenderCert")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	status, err := registerProcess(h, b.ProtectedPayload.GetPayload(), onboardCert[0])
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
	log.Printf("%s requested ping", r.RemoteAddr)
	// now just return a 200
	w.WriteHeader(http.StatusOK)
}

func (h *apiHandlerv2) config(w http.ResponseWriter, r *http.Request) {
	b, u := h.validateAuthContainerAndRecord(w, r)
	if u == nil {
		return
	}
	cfg, err := h.manager.GetConfig(*u, common.GetCreateBaseConfigHandler(h.ProtoFormat()))
	if err != nil {
		log.Printf("error getting device config: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	configRequest, err := h.getClientConfigRequest(b)
	if err != nil {
		log.Printf("error getting config request: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	data, code, err := configProcess(h, *u, configRequest, cfg, true)
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

func (h *apiHandlerv2) attest(w http.ResponseWriter, r *http.Request) {
	b, u := h.validateAuthContainerAndRecord(w, r)
	if u == nil {
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
	b, u := h.validateAuthContainerAndRecord(w, r)
	if u == nil {
		return
	}
	status, err := infoProcess(h, h.infoChannel, *u, b)
	if err != nil {
		log.Printf("Failed to infoProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

func (h *apiHandlerv2) metrics(w http.ResponseWriter, r *http.Request) {
	b, u := h.validateAuthContainerAndRecord(w, r)
	if u == nil {
		return
	}
	status, err := metricProcess(h, h.metricChannel, *u, b)
	if err != nil {
		log.Printf("Failed to metricProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

func (h *apiHandlerv2) logs(w http.ResponseWriter, r *http.Request) {
	b, u := h.validateAuthContainerAndRecord(w, r)
	if u == nil {
		return
	}

	status, err := logsProcess(h, h.logChannel, *u, b)
	if err != nil {
		log.Printf("Failed to logsProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

func (h *apiHandlerv2) newLogs(w http.ResponseWriter, r *http.Request) {
	b, u := h.validateAuthContainerAndRecord(w, r)
	if u == nil {
		return
	}

	status, err := newLogsProcess(h, h.logChannel, *u, bytes.NewReader(b))
	if err != nil {
		log.Printf("Failed to logsProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

func (h *apiHandlerv2) appLogs(w http.ResponseWriter, r *http.Request) {
	b, u := h.validateAuthContainerAndRecord(w, r)
	if u == nil {
		return
	}
	uid, err := uuid.FromString(mux.Vars(r)["appuuid"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	status, err := appLogsProcess(h, *u, uid, b)
	if err != nil {
		log.Printf("Failed to logsProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

func (h *apiHandlerv2) newAppLogs(w http.ResponseWriter, r *http.Request) {
	b, u := h.validateAuthContainerAndRecord(w, r)
	if u == nil {
		return
	}
	uid, err := uuid.FromString(mux.Vars(r)["appuuid"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	status, err := newAppLogsProcess(h, *u, uid, bytes.NewReader(b))
	if err != nil {
		log.Printf("Failed to logsProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

// retrieve the config request
func (h *apiHandlerv2) getClientConfigRequest(body []byte) (*config.ConfigRequest, error) {
	configRequest := &config.ConfigRequest{}
	err := proto.Unmarshal(body, configRequest)
	if err != nil {
		log.Printf("Unmarshalling failed: %v", err)
		return nil, err
	}
	return configRequest, nil
}

func (h *apiHandlerv2) flowlog(w http.ResponseWriter, r *http.Request) {
	b, u := h.validateAuthContainerAndRecord(w, r)
	if u == nil {
		return
	}
	status, err := flowLogProcess(h, *u, b)
	if err != nil {
		log.Printf("Failed to logsProcess: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(status)
}

func (h *apiHandlerv2) uuid(w http.ResponseWriter, r *http.Request) {
	b, u := h.validateAuthContainerAndRecord(w, r)
	if u == nil {
		return
	}

	var req eveuuid.UuidRequest
	err := proto.Unmarshal(b, &req)
	if err != nil {
		log.Printf("error unmarshalling uuidRequest: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	uuidResponce, err := h.manager.GetUUID(*u)
	if err != nil {
		log.Printf("error getting device uuidResponce: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	cloudEnvelope, eErr := h.prepareEnvelope(uuidResponce)
	if eErr != nil {
		msg := fmt.Sprintf("Error occurred while creating envelope: %v", eErr)
		log.Print(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	w.Header().Add(contentType, mimeProto)
	w.WriteHeader(http.StatusOK)
	w.Write(cloudEnvelope)
}
