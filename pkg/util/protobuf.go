package util

import (
	"bytes"
	"fmt"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
)

// ProtobufToBytes convert a protobuf to bytes
func ProtobufToBytes(msg proto.Message) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{})
	mler := jsonpb.Marshaler{}
	if err := mler.Marshal(buf, msg); err != nil {
		return nil, fmt.Errorf("failed to marshal protobuf message into json: %v", err)
	}
	return buf.Bytes(), nil
}
