package pppoe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	Version = 1
	Type    = 1

	CodeSession = 0x00
	CodePADI    = 0x09
	CodePADO    = 0x07
	CodePADR    = 0x19
	CodePADS    = 0x65
	CodePADT    = 0xa7

	TagEndOfList        uint16 = 0x0000
	TagServiceName      uint16 = 0x0101
	TagACName           uint16 = 0x0102
	TagHostUniq         uint16 = 0x0103
	TagACCookie         uint16 = 0x0104
	TagVendorSpecific   uint16 = 0x0105
	TagRelaySessionID   uint16 = 0x0110
	TagServiceNameError uint16 = 0x0201
	TagACSystemError    uint16 = 0x0202
	TagGenericError     uint16 = 0x0203

	HeaderLen = 6
)

var (
	ErrFrameTooShort  = errors.New("pppoe frame too short")
	ErrInvalidHeader  = errors.New("invalid pppoe header")
	ErrLengthMismatch = errors.New("pppoe payload length mismatch")
	ErrInvalidTag     = errors.New("invalid pppoe tag")
)

type Frame struct {
	Version   byte
	Type      byte
	Code      byte
	SessionID uint16
	Payload   []byte
	Tags      []Tag
}

type Tag struct {
	Type  uint16
	Value []byte
}

func ParseDiscoveryFrame(packet []byte) (Frame, error) {
	if len(packet) < HeaderLen {
		return Frame{}, ErrFrameTooShort
	}
	versionType := packet[0]
	version := versionType >> 4
	frameType := versionType & 0x0f
	if version != Version || frameType != Type {
		return Frame{}, fmt.Errorf("%w: version=%d type=%d", ErrInvalidHeader, version, frameType)
	}
	code := packet[1]
	if !IsDiscoveryCode(code) {
		return Frame{}, fmt.Errorf("%w: code=0x%02x is not a discovery code", ErrInvalidHeader, code)
	}
	length := int(binary.BigEndian.Uint16(packet[4:6]))
	if len(packet)-HeaderLen != length {
		return Frame{}, fmt.Errorf("%w: header=%d actual=%d", ErrLengthMismatch, length, len(packet)-HeaderLen)
	}
	payload := append([]byte(nil), packet[HeaderLen:]...)
	tags, err := ParseTags(payload)
	if err != nil {
		return Frame{}, err
	}
	return Frame{
		Version:   version,
		Type:      frameType,
		Code:      code,
		SessionID: binary.BigEndian.Uint16(packet[2:4]),
		Payload:   payload,
		Tags:      tags,
	}, nil
}

func ParseTags(payload []byte) ([]Tag, error) {
	tags := []Tag{}
	for offset := 0; offset < len(payload); {
		if len(payload)-offset < 4 {
			return nil, fmt.Errorf("%w at offset %d", ErrInvalidTag, offset)
		}
		tagType := binary.BigEndian.Uint16(payload[offset : offset+2])
		tagLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4
		if tagLen > len(payload)-offset {
			return nil, fmt.Errorf("%w type=0x%04x length=%d remaining=%d", ErrInvalidTag, tagType, tagLen, len(payload)-offset)
		}
		value := append([]byte(nil), payload[offset:offset+tagLen]...)
		tags = append(tags, Tag{Type: tagType, Value: value})
		offset += tagLen
		if tagType == TagEndOfList {
			break
		}
	}
	return tags, nil
}

func MarshalDiscoveryFrame(code byte, sessionID uint16, tags []Tag) ([]byte, error) {
	if !IsDiscoveryCode(code) {
		return nil, fmt.Errorf("%w: code=0x%02x is not a discovery code", ErrInvalidHeader, code)
	}
	payloadLen := 0
	for _, tag := range tags {
		if len(tag.Value) > 0xffff {
			return nil, fmt.Errorf("%w: tag 0x%04x exceeds 65535 bytes", ErrInvalidTag, tag.Type)
		}
		payloadLen += 4 + len(tag.Value)
	}
	if payloadLen > 0xffff {
		return nil, fmt.Errorf("%w: payload exceeds 65535 bytes", ErrInvalidTag)
	}
	out := make([]byte, HeaderLen+payloadLen)
	out[0] = byte(Version<<4) | byte(Type)
	out[1] = code
	binary.BigEndian.PutUint16(out[2:4], sessionID)
	binary.BigEndian.PutUint16(out[4:6], uint16(payloadLen))
	offset := HeaderLen
	for _, tag := range tags {
		binary.BigEndian.PutUint16(out[offset:offset+2], tag.Type)
		binary.BigEndian.PutUint16(out[offset+2:offset+4], uint16(len(tag.Value)))
		offset += 4
		copy(out[offset:offset+len(tag.Value)], tag.Value)
		offset += len(tag.Value)
	}
	return out, nil
}

func IsDiscoveryCode(code byte) bool {
	switch code {
	case CodePADI, CodePADO, CodePADR, CodePADS, CodePADT:
		return true
	default:
		return false
	}
}

func TagValueString(tags []Tag, tagType uint16) (string, bool) {
	for _, tag := range tags {
		if tag.Type == tagType {
			return string(tag.Value), true
		}
	}
	return "", false
}
