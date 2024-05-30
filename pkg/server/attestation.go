// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"log"
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-tpm/tpm2"
	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/adam/pkg/driver/common"
	x509Pem "github.com/lf-edge/adam/pkg/x509"
	"github.com/lf-edge/eve-api/go/attest"
	"github.com/lf-edge/eve-api/go/certs"
	uuid "github.com/satori/go.uuid"
)

// extractQuoteAttestTemplate process attestation quote and return internal structure with provided data
func extractQuoteAttestTemplate(quote *attest.ZAttestQuote) *common.PCRTemplate {
	template := common.PCRTemplate{}
	for _, el := range quote.GetPcrValues() {
		template.PCRValues = append(template.PCRValues, &common.PCRValue{
			Index: el.GetIndex(),
			Value: hex.EncodeToString(el.GetValue()),
		})
	}
	for _, versionInfo := range quote.GetVersions() {
		switch versionInfo.VersionType {
		case attest.AttestVersionType_ATTEST_VERSION_TYPE_EVE:
			template.EveVersion = versionInfo.Version
		case attest.AttestVersionType_ATTEST_VERSION_TYPE_FIRMWARE:
			template.FirmwareVersion = versionInfo.Version
		}
	}
	return &template
}

// quoteValidate validates nonce, algo and hash of provided quote
// it modifies resp.Response field in case of errors
func quoteValidate(manager driver.DeviceManager, u uuid.UUID, quote *attest.ZAttestQuote, resp *attest.ZAttestQuoteResp) error {
	deviceOptions, err := getDeviceOptions(manager, u)
	if err != nil {
		return err
	}
	if len(deviceOptions.Nonce) == 0 {
		resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_NONCE_MISMATCH
		return fmt.Errorf("empty nonce for device in controller")
	}
	attestDataHash := sha256.Sum256(quote.GetAttestData())
	deviceCertsBytes, err := manager.GetCerts(u)
	if err != nil {
		resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_NO_CERT_FOUND
		return fmt.Errorf("cannot get device certs: %s", err)
	}
	var deviceCerts common.Zcerts
	err = json.Unmarshal(deviceCertsBytes, &deviceCerts)
	if err != nil {
		resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_INVALID
		return fmt.Errorf("cannot unmarshal device certs: %s", err)
	}
	var signingCert *certs.ZCert
	for _, el := range deviceCerts.Certs {
		if el.Type == certs.ZCertType_CERT_TYPE_DEVICE_RESTRICTED_SIGNING {
			signingCert = el
			break
		}
	}
	if signingCert == nil {
		resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_NO_CERT_FOUND
		return fmt.Errorf("cannot get device signing cert")
	}
	cert, err := x509Pem.ParseCert(signingCert.GetCert())
	if err != nil {
		resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_NO_CERT_FOUND
		return fmt.Errorf("cannot parse device cert: %s", err)
	}
	err = verifySignature(quote.GetSignature(), attestDataHash[:], cert)
	if err != nil {
		resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_INVALID
		return fmt.Errorf("cannot get device certs: %s", err)
	}
	attestData, err := tpm2.DecodeAttestationData(quote.GetAttestData())
	if err != nil {
		resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_INVALID
		return fmt.Errorf("cannot decode attestation data: %s", err)
	}
	if attestData.Type != tpm2.TagAttestQuote {
		resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_INVALID
		return fmt.Errorf("wrong type of attestation data")
	}

	if !bytes.Equal(attestData.ExtraData, []byte(deviceOptions.Nonce)) {
		resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_NONCE_MISMATCH
		return fmt.Errorf("nonce missmatch")
	}

	pcrMap := map[int][]byte{}
	expectedDigestAlgo := attestData.AttestedQuoteInfo.PCRSelection.Hash
	var tpmHashAlgo attest.TpmHashAlgo
	var hashObj hash.Hash
	switch expectedDigestAlgo {
	case tpm2.AlgSHA256:
		tpmHashAlgo = attest.TpmHashAlgo_TPM_HASH_ALGO_SHA256
		hashObj = sha256.New()
	default:
		resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_QUOTE_FAILED
		return fmt.Errorf("unexpected hash algo: %s", expectedDigestAlgo)
	}

	for _, pcr := range quote.GetPcrValues() {
		if pcr.GetHashAlgo() == tpmHashAlgo {
			pcrMap[int(pcr.GetIndex())] = pcr.GetValue()
		} else {
			resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_QUOTE_FAILED
			return fmt.Errorf("PCR %d hash algo %s is different from expected value %s",
				pcr.GetIndex(), pcr.GetHashAlgo(), tpmHashAlgo)
		}
	}

	for _, i := range attestData.AttestedQuoteInfo.PCRSelection.PCRs {
		v, ok := pcrMap[i]
		if !ok {
			resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_QUOTE_FAILED
			return fmt.Errorf("found invalid PCR index %d", i)
		}
		if _, err := hashObj.Write(v); err != nil {
			log.Printf("cannot write to hash: %s", err)
		}
	}

	if !bytes.Equal(hashObj.Sum(nil), attestData.AttestedQuoteInfo.PCRDigest) {
		resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_QUOTE_FAILED
		return fmt.Errorf("quote digest didn't match with provided digest")
	}
	return nil
}

// templateAttest checks provided quote against saved template
func templateAttest(manager driver.DeviceManager, u uuid.UUID, quote *attest.ZAttestQuote, resp *attest.ZAttestQuoteResp) error {
	deviceOptions, err := getDeviceOptions(manager, u)
	if err != nil {
		return err
	}
	attestTemplate := extractQuoteAttestTemplate(quote)
	deviceOptions.ReceivedPCRTemplate = attestTemplate
	deviceOptions.EventLog = quote.EventLog
	err = setDeviceOptions(manager, u, deviceOptions)
	if err != nil {
		return err
	}
	globalOptions, err := getGlobalOptions(manager)
	if err != nil {
		return err
	}
	// skip template attestation if not enforced
	if !globalOptions.EnforceTemplateAttestation {
		return nil
	}
	eveVersion := ""
	firmwareVersion := ""
	for _, versionInfo := range quote.GetVersions() {
		switch versionInfo.VersionType {
		case attest.AttestVersionType_ATTEST_VERSION_TYPE_EVE:
			eveVersion = versionInfo.Version
		case attest.AttestVersionType_ATTEST_VERSION_TYPE_FIRMWARE:
			firmwareVersion = versionInfo.Version
		}
	}
	if eveVersion == "" {
		resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_INVALID
		return fmt.Errorf("no EVE version found in quote")
	}
	var currentTemplate *common.PCRTemplate
	for _, el := range globalOptions.PCRTemplates {
		if el.EveVersion == eveVersion {
			currentTemplate = el
			// firmware version is optional
			if el.FirmwareVersion == firmwareVersion {
				break
			}
		}
	}
	if currentTemplate == nil {
		resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_INVALID
		return fmt.Errorf("no template found for version %s and firmware %s", eveVersion, firmwareVersion)
	}
	devicePCRs := map[uint32]string{}
	for _, pcr := range quote.GetPcrValues() {
		// we store hex-encoded strings inside template
		devicePCRs[pcr.GetIndex()] = hex.EncodeToString(pcr.GetValue())
	}

	for _, pcr := range currentTemplate.PCRValues {
		// skip empty and wildcard
		if pcr.Value == "" || pcr.Value == "*" {
			continue
		}
		val, ok := devicePCRs[pcr.Index]
		if !ok {
			resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_QUOTE_FAILED
			return fmt.Errorf("PCR index %d not found in device", pcr.Index)
		}
		if val != pcr.Value {
			resp.Response = attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_QUOTE_FAILED
			return fmt.Errorf("PCR index %d value missmatch. Expected %s, received %s", pcr.Index, pcr.Value, val)
		}
	}

	return nil
}

func attestProcess(manager driver.DeviceManager, u uuid.UUID, b []byte) ([]byte, int, error) {
	msg := &attest.ZAttestReq{}
	if err := proto.Unmarshal(b, msg); err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("failed to parse attest request: %v", err)
	}
	deviceOptions, err := getDeviceOptions(manager, u)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to get device options: %v", err)
	}
	response := &attest.ZAttestResponse{}
	switch msg.ReqType {
	case attest.ZAttestReqType_ATTEST_REQ_NONCE:
		response.RespType = attest.ZAttestRespType_ATTEST_RESP_NONCE
		nonce := randomString(nonceSize)
		deviceOptions.Nonce = nonce
		//new attestation process
		deviceOptions.Attested = false
		if err := setDeviceOptions(manager, u, deviceOptions); err != nil {
			log.Printf("Cannot store device options: %s", err)
		}
		response.Nonce = &attest.ZAttestNonceResp{Nonce: []byte(nonce)}
	case attest.ZAttestReqType_ATTEST_REQ_CERT:
		certsData := &common.Zcerts{Certs: msg.Certs}
		b, err := json.Marshal(certsData)
		if err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("failed to marshal attest message: %v", err)
		}
		err = manager.WriteCerts(u, b)
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("failed to write attest certs message: %v", err)
		}
		response.RespType = attest.ZAttestRespType_ATTEST_RESP_CERT
	case attest.ZAttestReqType_ATTEST_REQ_QUOTE:
		var keys []*attest.AttestVolumeKey
		b, err := manager.GetStorageKeys(u)
		if err == nil && len(b) > 0 {
			var storageKeys attest.AttestStorageKeys
			err = json.Unmarshal(b, &storageKeys)
			if err != nil {
				log.Printf("cannot unmarshal storage keys: %s", err)
			} else {
				keys = storageKeys.GetKeys()
			}
		}
		integrityToken := deviceOptions.IntegrityToken
		if integrityToken == "" {
			integrityToken = randomString(integrityTokenSize)
			deviceOptions.IntegrityToken = integrityToken
			if err := setDeviceOptions(manager, u, deviceOptions); err != nil {
				log.Printf("Cannot store device options: %s", err)
			}
		}
		response.RespType = attest.ZAttestRespType_ATTEST_RESP_QUOTE_RESP
		response.QuoteResp = &attest.ZAttestQuoteResp{
			IntegrityToken: []byte(integrityToken),
			Keys:           keys,
			Response:       attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_SUCCESS,
		}

		// no data provided, assume that TPM disabled
		if msg.Quote == nil || len(msg.Quote.GetPcrValues()) == 0 {
			response.QuoteResp.Keys = nil
			if !deviceOptions.Attested {
				deviceOptions.Attested = true
				if err := setDeviceOptions(manager, u, deviceOptions); err != nil {
					log.Printf("Cannot store device options: %s", err)
				}
			}
			break
		}

		if err := quoteValidate(manager, u, msg.Quote, response.QuoteResp); err != nil {
			if response.QuoteResp.Response != attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_SUCCESS {
				response.QuoteResp.IntegrityToken = nil
				response.QuoteResp.Keys = nil
				log.Printf("quoteValidate failed: %s, %s", response.QuoteResp.Response, err)
				break
			}
		}

		if err := templateAttest(manager, u, msg.Quote, response.QuoteResp); err != nil {
			if response.QuoteResp.Response != attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_SUCCESS {
				response.QuoteResp.IntegrityToken = nil
				response.QuoteResp.Keys = nil
				log.Printf("templateAttest failed: %s, %s", response.QuoteResp.Response, err)
				break
			}
		}

		if !deviceOptions.Attested {
			deviceOptions.Attested = true
			if err := setDeviceOptions(manager, u, deviceOptions); err != nil {
				log.Printf("Cannot store device options: %s", err)
			}
		}

	case attest.ZAttestReqType_Z_ATTEST_REQ_TYPE_STORE_KEYS:
		response.RespType = attest.ZAttestRespType_Z_ATTEST_RESP_TYPE_STORE_KEYS
		if len(msg.StorageKeys.IntegrityToken) == 0 || !bytes.Equal(msg.StorageKeys.IntegrityToken, []byte(deviceOptions.IntegrityToken)) {
			response.StorageKeysResp = &attest.AttestStorageKeysResp{
				Response: attest.AttestStorageKeysResponseCode_ATTEST_STORAGE_KEYS_RESPONSE_CODE_ITOKEN_MISMATCH,
			}
			break
		}
		storageKeys := msg.StorageKeys
		b, err := json.Marshal(storageKeys)
		if err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("failed to marshal storage keys: %s", err)
		}
		err = manager.WriteStorageKeys(u, b)
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("failed to write storage keys message: %v", err)
		}
		response.StorageKeysResp = &attest.AttestStorageKeysResp{
			Response: attest.AttestStorageKeysResponseCode_ATTEST_STORAGE_KEYS_RESPONSE_CODE_SUCCESS,
		}
	default:
		return nil, http.StatusBadRequest, fmt.Errorf("failed to process attest request: not implemented for type %v", msg.ReqType)
	}
	out, err := proto.Marshal(response)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("error converting config to byte message %v", msg.ReqType)
	}
	return out, http.StatusCreated, nil
}
