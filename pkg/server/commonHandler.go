// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/adam/pkg/driver/common"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/register"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	contentType   = "Content-Type"
	accept        = "Accept"
	mimeProto     = "application/x-proto-binary"
	mimeTextPlain = "text/plain"
	mimeJSON      = "application/json"
)

func configProcess(manager driver.DeviceManager, u uuid.UUID, configRequest *config.ConfigRequest, conf []byte, enforceIntegrityCheck bool) ([]byte, int, error) {
	deviceOptions, err := getDeviceOptions(manager, u)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to get device options: %v", err)
	}
	if enforceIntegrityCheck {
		if len(configRequest.IntegrityToken) == 0 || !bytes.Equal(configRequest.IntegrityToken, []byte(deviceOptions.IntegrityToken)) {
			return nil, http.StatusForbidden, fmt.Errorf("integrity token missmatch")
		}
	}
	// convert config into a protobuf
	var msg config.EdgeDevConfig
	if err := proto.Unmarshal(conf, &msg); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("error reading device config: %v", err)
	}
	response := &config.ConfigResponse{}

	hash := sha256.New()
	common.ComputeConfigElementSha(hash, &msg)
	configHash := hash.Sum(nil)

	response.Config = &msg
	response.ConfigHash = base64.URLEncoding.EncodeToString(configHash)

	if configRequest != nil {
		//compare received config hash with current
		if strings.Compare(configRequest.ConfigHash, response.ConfigHash) == 0 {
			return nil, http.StatusNotModified, nil
		}
	}

	out, err := proto.Marshal(response)
	if err != nil {
		log.Printf("error converting config to byte message: %v", err)
	}
	return out, http.StatusOK, nil
}

func registerProcess(manager driver.DeviceManager, registerMessage []byte, onboardCert *x509.Certificate) (int, error) {
	msg := &register.ZRegisterMsg{}
	if err := proto.Unmarshal(registerMessage, msg); err != nil {
		return http.StatusBadRequest, fmt.Errorf("failed to parse register message: %v", err)
	}
	serial := msg.Serial
	err := manager.OnboardCheck(onboardCert, serial)
	if err != nil {
		log.Printf("failed to onboard with serial: %s", err)
		if msg.SoftSerial != "" {
			log.Println("will retry with soft serial")
			serial = msg.SoftSerial
			err = manager.OnboardCheck(onboardCert, serial)
		}
		if err != nil {
			_, invalidCert := err.(*common.InvalidCertError)
			_, invalidSerial := err.(*common.InvalidSerialError)
			_, usedSerial := err.(*common.UsedSerialError)
			switch {
			case invalidCert, invalidSerial:
				return http.StatusUnauthorized, fmt.Errorf("failed authentication %v", err)
			case usedSerial:
				return http.StatusConflict, fmt.Errorf("used serial %v", err)
			}
			return http.StatusInternalServerError, fmt.Errorf("error checking onboard cert and serial: %v", err)
		}
	}
	// the passed cert is base64 encoded PEM. So we need to base64 decode it, and then extract the DER bytes
	// register the new device cert
	certPemBytes, err := base64.StdEncoding.DecodeString(string(msg.PemCert))
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("error base64-decoding device certficate from registration: %v", err)
	}

	certDer, _ := pem.Decode(certPemBytes)
	deviceCert, err := x509.ParseCertificate(certDer.Bytes)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("unable to convert device cert data from message to x509 certificate: %v", err)
	}
	// generate a new uuid
	unew, err := uuid.NewV4()
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("error generating a new device UUID: %v", err)
	}
	// we do not keep the uuid or send it back; perhaps a future version of the API will support it
	if err := manager.DeviceRegister(unew, deviceCert, onboardCert, serial, common.CreateBaseConfig(unew)); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("error registering new device: %v", err)
	}
	// send back a 201
	return http.StatusCreated, nil
}

func infoProcess(manager driver.DeviceManager, infoChannel chan []byte, u uuid.UUID, infoMessage []byte) (int, error) {
	var err error
	select {
	case infoChannel <- infoMessage:
	default:
	}
	err = manager.WriteInfo(u, infoMessage)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to write info message: %v", err)
	}
	// send back a 201
	return http.StatusCreated, nil
}

func metricProcess(manager driver.DeviceManager, metricChannel chan []byte, u uuid.UUID, metricMessage []byte) (int, error) {
	var err error
	select {
	case metricChannel <- metricMessage:
	default:
	}
	err = manager.WriteMetrics(u, metricMessage)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to write metric message: %v", err)
	}
	// send back a 201
	return http.StatusCreated, nil
}

func logsProcess(manager driver.DeviceManager, logsChannel chan []byte, u uuid.UUID, logsMessage []byte) (int, error) {
	var err error
	msg := &logs.LogBundle{}
	if err := proto.Unmarshal(logsMessage, msg); err != nil {
		return http.StatusBadRequest, fmt.Errorf("error parsing logbundle message: %v", err)
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
			return http.StatusBadRequest, fmt.Errorf("failed to marshal FullLogEntry message: %v", err)
		}
		select {
		case logsChannel <- entryBytes:
		default:
		}
		err = manager.WriteLogs(u, entryBytes)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("failed to write logs message: %v", err)
		}
	}
	// send back a 201
	return http.StatusCreated, nil
}

func newLogsProcess(manager driver.DeviceManager, logsChannel chan []byte, u uuid.UUID, reader io.Reader) (int, error) {
	gr, err := gzip.NewReader(reader)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("error gzip.NewReader: %v", err)
	}
	msg := &logs.LogBundle{}
	if err := json.Unmarshal([]byte(gr.Comment), msg); err != nil {
		return http.StatusBadRequest, fmt.Errorf("error parsing logbundle message from Comment: %v", err)
	}
	scanner := bufio.NewScanner(gr)
	for scanner.Scan() {
		le := &logs.LogEntry{}
		if err := json.Unmarshal(scanner.Bytes(), le); err != nil {
			return http.StatusBadRequest, fmt.Errorf("failed to parse logentry message: %v", err)
		}
		entry := &common.FullLogEntry{
			LogEntry:   le,
			Image:      msg.GetImage(),
			EveVersion: msg.GetEveVersion(),
		}
		var entryBytes []byte
		if entryBytes, err = entry.Json(); err != nil {
			return http.StatusBadRequest, fmt.Errorf("failed to marshal FullLogEntry message: %v", err)
		}
		select {
		case logsChannel <- entryBytes:
		default:
		}
		err = manager.WriteLogs(u, entryBytes)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("failed to write logs message: %v", err)
		}
	}
	// send back a 201
	return http.StatusCreated, nil
}

func appLogsProcess(manager driver.DeviceManager, u, appID uuid.UUID, logsMessage []byte) (int, error) {
	msg := &logs.AppInstanceLogBundle{}
	if err := proto.Unmarshal(logsMessage, msg); err != nil {
		return http.StatusBadRequest, fmt.Errorf("error parsing appinstancelogbundle message: %v", err)
	}
	for _, le := range msg.Log {
		var err error
		var b []byte
		if b, err = protojson.Marshal(le); err != nil {
			return http.StatusBadRequest, fmt.Errorf("failed to marshal LogEntry message: %v", err)
		}
		err = manager.WriteAppInstanceLogs(appID, u, b)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("failed to write appinstancelogbundle message: %v", err)
		}
	}
	// send back a 201
	return http.StatusCreated, nil
}

func newAppLogsProcess(manager driver.DeviceManager, u, appID uuid.UUID, reader io.Reader) (int, error) {
	gr, err := gzip.NewReader(reader)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("error gzip.NewReader: %v", err)
	}
	scanner := bufio.NewScanner(gr)
	for scanner.Scan() {
		le := &logs.LogEntry{}
		if err := json.Unmarshal(scanner.Bytes(), le); err != nil {
			return http.StatusBadRequest, fmt.Errorf("failed to parse logentry message: %v", err)
		}
		var b []byte
		if b, err = protojson.Marshal(le); err != nil {
			return http.StatusBadRequest, fmt.Errorf("failed to marshal LogEntry message: %v", err)
		}
		err = manager.WriteAppInstanceLogs(appID, u, b)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("failed to write logs message: %v", err)
		}
	}
	// send back a 201
	return http.StatusCreated, nil
}

func setDeviceOptions(manager driver.DeviceManager, u uuid.UUID, deviceOptions *common.DeviceOptions) error {
	b, err := json.Marshal(deviceOptions)
	if err != nil {
		return fmt.Errorf("cannot marshal device options: %s", err)
	}
	return manager.SetDeviceOptions(u, b)
}

func getDeviceOptions(manager driver.DeviceManager, u uuid.UUID) (*common.DeviceOptions, error) {
	deviceOptionsBytes, err := manager.GetDeviceOptions(u)
	if err != nil {
		return nil, fmt.Errorf("getDeviceOptions failed to get from manager: %s", err)
	}
	var deviceOptions common.DeviceOptions
	if err := json.Unmarshal(deviceOptionsBytes, &deviceOptions); err != nil {
		return nil, fmt.Errorf("getDeviceOptions failed to unmarshal: %s", err)
	}
	return &deviceOptions, nil
}

func getGlobalOptions(manager driver.DeviceManager) (*common.GlobalOptions, error) {
	globalOptionsBytes, err := manager.GetGlobalOptions()
	if err != nil {
		return nil, fmt.Errorf("getGlobalOptions failed to get from manager: %s", err)
	}
	var globalOptions common.GlobalOptions
	if err := json.Unmarshal(globalOptionsBytes, &globalOptions); err != nil {
		return nil, fmt.Errorf("getGlobalOptions failed to unmarshal: %s", err)
	}
	return &globalOptions, nil
}

func randomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, length)
	rand.Read(b)
	return fmt.Sprintf("%x", b)[:length]
}

func flowLogProcess(manager driver.DeviceManager, u uuid.UUID, flowMessage []byte) (int, error) {
	var err error
	err = manager.WriteFlowMessage(u, flowMessage)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to write FlowMessage: %v", err)
	}
	// send back a 201
	return http.StatusCreated, nil
}
