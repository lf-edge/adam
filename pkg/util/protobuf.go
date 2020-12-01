package util

import (
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// ProtobufToBytes convert a protobuf to bytes
func ProtobufToBytes(msg proto.Message) ([]byte, error) {
	return protojson.Marshal(msg)
}
