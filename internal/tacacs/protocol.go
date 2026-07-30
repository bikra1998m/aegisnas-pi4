package tacacs

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	ProtocolSchemaVersion = 1

	VersionDefault byte = 0xc0

	TypeAuthentication byte = 0x01
	TypeAuthorization  byte = 0x02
	TypeAccounting     byte = 0x03

	FlagUnencrypted   byte = 0x01
	FlagSingleConnect byte = 0x04

	AuthenActionLogin byte = 0x01

	AuthenTypeASCII byte = 0x01
	AuthenTypePAP   byte = 0x02

	AuthenServiceLogin  byte = 0x01
	AuthenServiceEnable byte = 0x02
	AuthenServicePPP    byte = 0x03
	AuthenServiceShell  byte = 0x06

	AuthenStatusPass    byte = 0x01
	AuthenStatusFail    byte = 0x02
	AuthenStatusGetData byte = 0x03
	AuthenStatusGetUser byte = 0x04
	AuthenStatusGetPass byte = 0x05
	AuthenStatusRestart byte = 0x06
	AuthenStatusError   byte = 0x07

	AuthorStatusPassAdd  byte = 0x01
	AuthorStatusPassRepl byte = 0x02
	AuthorStatusFail     byte = 0x10
	AuthorStatusError    byte = 0x11

	AcctStatusSuccess byte = 0x01
	AcctStatusError   byte = 0x02
	AcctStatusFollow  byte = 0x21
)

type Header struct {
	Version   byte   `json:"version"`
	Type      byte   `json:"type"`
	SeqNo     byte   `json:"seq_no"`
	Flags     byte   `json:"flags"`
	SessionID uint32 `json:"session_id"`
	Length    uint32 `json:"length"`
}

type Packet struct {
	Header Header `json:"header"`
	Body   []byte `json:"body"`
}

type AuthenStart struct {
	Action        byte
	Privilege     byte
	AuthenType    byte
	Service       byte
	User          string
	Port          string
	RemoteAddress string
	Data          []byte
}

type AuthenReply struct {
	Status    byte
	Flags     byte
	ServerMsg string
	Data      []byte
}

type AuthenContinue struct {
	UserMsg string
	Data    []byte
	Flags   byte
}

type AuthorRequest struct {
	AuthenMethod  byte
	Privilege     byte
	AuthenType    byte
	Service       byte
	User          string
	Port          string
	RemoteAddress string
	Args          []string
}

type AuthorResponse struct {
	Status    byte
	ServerMsg string
	Data      string
	Args      []string
}

type AcctRequest struct {
	Flags         byte
	AuthenMethod  byte
	Privilege     byte
	AuthenType    byte
	Service       byte
	User          string
	Port          string
	RemoteAddress string
	Args          []string
}

type AcctResponse struct {
	Status    byte
	ServerMsg string
	Data      string
}

func ReadPacket(r io.Reader, secret string, maxPacketBytes int, allowUnencrypted bool) (Packet, error) {
	headerBytes := make([]byte, 12)
	if _, err := io.ReadFull(r, headerBytes); err != nil {
		return Packet{}, err
	}
	header := Header{
		Version:   headerBytes[0],
		Type:      headerBytes[1],
		SeqNo:     headerBytes[2],
		Flags:     headerBytes[3],
		SessionID: binary.BigEndian.Uint32(headerBytes[4:8]),
		Length:    binary.BigEndian.Uint32(headerBytes[8:12]),
	}
	if header.Version>>4 != 0x0c {
		return Packet{}, fmt.Errorf("unsupported TACACS+ version 0x%02x", header.Version)
	}
	if header.Length > uint32(maxPacketLimit(maxPacketBytes)) {
		return Packet{}, fmt.Errorf("TACACS+ packet body length %d exceeds limit", header.Length)
	}
	body := make([]byte, header.Length)
	if _, err := io.ReadFull(r, body); err != nil {
		return Packet{}, err
	}
	if header.Flags&FlagUnencrypted != 0 {
		if !allowUnencrypted {
			return Packet{}, errors.New("unencrypted TACACS+ packet is not allowed")
		}
		return Packet{Header: header, Body: body}, nil
	}
	if secret == "" {
		return Packet{}, errors.New("encrypted TACACS+ packet requires a shared secret")
	}
	xorBody(body, header, []byte(secret))
	return Packet{Header: header, Body: body}, nil
}

func WritePacket(w io.Writer, packet Packet, secret string) error {
	body := append([]byte(nil), packet.Body...)
	header := packet.Header
	header.Length = uint32(len(body))
	if header.Version == 0 {
		header.Version = VersionDefault
	}
	if header.SeqNo == 0 {
		header.SeqNo = 1
	}
	if header.Flags&FlagUnencrypted == 0 {
		if secret == "" {
			return errors.New("encrypted TACACS+ packet requires a shared secret")
		}
		xorBody(body, header, []byte(secret))
	}
	headerBytes := make([]byte, 12)
	headerBytes[0] = header.Version
	headerBytes[1] = header.Type
	headerBytes[2] = header.SeqNo
	headerBytes[3] = header.Flags
	binary.BigEndian.PutUint32(headerBytes[4:8], header.SessionID)
	binary.BigEndian.PutUint32(headerBytes[8:12], header.Length)
	if _, err := w.Write(headerBytes); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func ParseAuthenStart(body []byte) (AuthenStart, error) {
	if len(body) < 8 {
		return AuthenStart{}, errors.New("authentication start body too short")
	}
	req := AuthenStart{
		Action:     body[0],
		Privilege:  body[1],
		AuthenType: body[2],
		Service:    body[3],
	}
	userLen, portLen, remLen, dataLen := int(body[4]), int(body[5]), int(body[6]), int(body[7])
	offset := 8
	var err error
	if req.User, offset, err = readString(body, offset, userLen); err != nil {
		return AuthenStart{}, err
	}
	if req.Port, offset, err = readString(body, offset, portLen); err != nil {
		return AuthenStart{}, err
	}
	if req.RemoteAddress, offset, err = readString(body, offset, remLen); err != nil {
		return AuthenStart{}, err
	}
	if offset+dataLen > len(body) {
		return AuthenStart{}, errors.New("authentication data exceeds body length")
	}
	req.Data = append([]byte(nil), body[offset:offset+dataLen]...)
	return req, nil
}

func MarshalAuthenReply(reply AuthenReply) ([]byte, error) {
	if len(reply.ServerMsg) > 65535 || len(reply.Data) > 65535 {
		return nil, errors.New("authentication reply message is too large")
	}
	body := make([]byte, 6, 6+len(reply.ServerMsg)+len(reply.Data))
	body[0] = reply.Status
	body[1] = reply.Flags
	binary.BigEndian.PutUint16(body[2:4], uint16(len(reply.ServerMsg)))
	binary.BigEndian.PutUint16(body[4:6], uint16(len(reply.Data)))
	body = append(body, []byte(reply.ServerMsg)...)
	body = append(body, reply.Data...)
	return body, nil
}

func ParseAuthenContinue(body []byte) (AuthenContinue, error) {
	if len(body) < 5 {
		return AuthenContinue{}, errors.New("authentication continue body too short")
	}
	userMsgLen := int(binary.BigEndian.Uint16(body[0:2]))
	dataLen := int(binary.BigEndian.Uint16(body[2:4]))
	cont := AuthenContinue{Flags: body[4]}
	offset := 5
	var err error
	if cont.UserMsg, offset, err = readString(body, offset, userMsgLen); err != nil {
		return AuthenContinue{}, err
	}
	if offset+dataLen > len(body) {
		return AuthenContinue{}, errors.New("authentication continue data exceeds body length")
	}
	cont.Data = append([]byte(nil), body[offset:offset+dataLen]...)
	return cont, nil
}

func ParseAuthorRequest(body []byte, maxArgs int) (AuthorRequest, error) {
	if len(body) < 8 {
		return AuthorRequest{}, errors.New("authorization request body too short")
	}
	req := AuthorRequest{
		AuthenMethod: body[0],
		Privilege:    body[1],
		AuthenType:   body[2],
		Service:      body[3],
	}
	userLen, portLen, remLen, argCount := int(body[4]), int(body[5]), int(body[6]), int(body[7])
	if argCount > maxArgLimit(maxArgs) {
		return AuthorRequest{}, fmt.Errorf("authorization arg count %d exceeds limit", argCount)
	}
	if len(body) < 8+argCount {
		return AuthorRequest{}, errors.New("authorization arg lengths exceed body length")
	}
	argLens := body[8 : 8+argCount]
	offset := 8 + argCount
	var err error
	if req.User, offset, err = readString(body, offset, userLen); err != nil {
		return AuthorRequest{}, err
	}
	if req.Port, offset, err = readString(body, offset, portLen); err != nil {
		return AuthorRequest{}, err
	}
	if req.RemoteAddress, offset, err = readString(body, offset, remLen); err != nil {
		return AuthorRequest{}, err
	}
	req.Args = make([]string, 0, argCount)
	for _, length := range argLens {
		var value string
		if value, offset, err = readString(body, offset, int(length)); err != nil {
			return AuthorRequest{}, err
		}
		req.Args = append(req.Args, value)
	}
	return req, nil
}

func MarshalAuthorResponse(resp AuthorResponse) ([]byte, error) {
	if len(resp.ServerMsg) > 65535 || len(resp.Data) > 65535 || len(resp.Args) > 255 {
		return nil, errors.New("authorization response is too large")
	}
	body := make([]byte, 6, 6+len(resp.ServerMsg)+len(resp.Data))
	body[0] = resp.Status
	body[1] = byte(len(resp.Args))
	binary.BigEndian.PutUint16(body[2:4], uint16(len(resp.ServerMsg)))
	binary.BigEndian.PutUint16(body[4:6], uint16(len(resp.Data)))
	for _, arg := range resp.Args {
		if len(arg) > 255 {
			return nil, errors.New("authorization response arg is too large")
		}
		body = append(body, byte(len(arg)))
	}
	body = append(body, []byte(resp.ServerMsg)...)
	body = append(body, []byte(resp.Data)...)
	for _, arg := range resp.Args {
		body = append(body, []byte(arg)...)
	}
	return body, nil
}

func ParseAcctRequest(body []byte, maxArgs int) (AcctRequest, error) {
	if len(body) < 9 {
		return AcctRequest{}, errors.New("accounting request body too short")
	}
	req := AcctRequest{
		Flags:        body[0],
		AuthenMethod: body[1],
		Privilege:    body[2],
		AuthenType:   body[3],
		Service:      body[4],
	}
	userLen, portLen, remLen, argCount := int(body[5]), int(body[6]), int(body[7]), int(body[8])
	if argCount > maxArgLimit(maxArgs) {
		return AcctRequest{}, fmt.Errorf("accounting arg count %d exceeds limit", argCount)
	}
	if len(body) < 9+argCount {
		return AcctRequest{}, errors.New("accounting arg lengths exceed body length")
	}
	argLens := body[9 : 9+argCount]
	offset := 9 + argCount
	var err error
	if req.User, offset, err = readString(body, offset, userLen); err != nil {
		return AcctRequest{}, err
	}
	if req.Port, offset, err = readString(body, offset, portLen); err != nil {
		return AcctRequest{}, err
	}
	if req.RemoteAddress, offset, err = readString(body, offset, remLen); err != nil {
		return AcctRequest{}, err
	}
	req.Args = make([]string, 0, argCount)
	for _, length := range argLens {
		var value string
		if value, offset, err = readString(body, offset, int(length)); err != nil {
			return AcctRequest{}, err
		}
		req.Args = append(req.Args, value)
	}
	return req, nil
}

func MarshalAcctResponse(resp AcctResponse) ([]byte, error) {
	if len(resp.ServerMsg) > 65535 || len(resp.Data) > 65535 {
		return nil, errors.New("accounting response is too large")
	}
	body := make([]byte, 5, 5+len(resp.ServerMsg)+len(resp.Data))
	binary.BigEndian.PutUint16(body[0:2], uint16(len(resp.ServerMsg)))
	binary.BigEndian.PutUint16(body[2:4], uint16(len(resp.Data)))
	body[4] = resp.Status
	body = append(body, []byte(resp.ServerMsg)...)
	body = append(body, []byte(resp.Data)...)
	return body, nil
}

func readString(body []byte, offset, length int) (string, int, error) {
	if length < 0 || offset < 0 || offset+length > len(body) {
		return "", offset, errors.New("TACACS+ string exceeds body length")
	}
	return string(body[offset : offset+length]), offset + length, nil
}

func xorBody(body []byte, header Header, secret []byte) {
	var previous []byte
	offset := 0
	sessionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sessionBytes, header.SessionID)
	for offset < len(body) {
		hash := md5.New()
		hash.Write(sessionBytes)
		hash.Write(secret)
		hash.Write([]byte{header.Version, header.SeqNo})
		if len(previous) > 0 {
			hash.Write(previous)
		}
		pad := hash.Sum(nil)
		previous = pad
		for i := 0; i < len(pad) && offset < len(body); i++ {
			body[offset] ^= pad[i]
			offset++
		}
	}
}

func maxPacketLimit(value int) int {
	if value <= 0 || value > 65535 {
		return 65535
	}
	return value
}

func maxArgLimit(value int) int {
	if value <= 0 || value > 255 {
		return 255
	}
	return value
}
