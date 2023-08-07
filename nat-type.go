package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"math/rand"
	"net"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// Message Types
const (
	BindingRequest            = 0x0001
	BindingResponse           = 0x0101
	BindingErrorResponse      = 0x0111
	SharedSecretRequest       = 0x0002
	SharedSecretResponse      = 0x0102
	SharedSecretErrorResponse = 0x0112
)

// Attributes Types
const (
	MappedAddress     = 0x0001
	ResponseAddress   = 0x0002
	ChangeRequest     = 0x0003
	SourceAddress     = 0x0004
	ChangedAddress    = 0x0005
	Username          = 0x0006
	Password          = 0x0007
	MessageIntegrity  = 0x0008
	ErrorCode         = 0x0009
	UnknownAttributes = 0x000a
	ReflectedFrom     = 0x000b
	XORMappedAddress  = 0x0020
	ResponseOrigin    = 0x802b
	OtherAddress      = 0x802c
)

var (
	MagicCookie         = [4]byte{0x21, 0x12, 0xA4, 0x42}
	ChangeIPAttr        = [4]byte{0, 0, 0, 0x4}
	ChangePortAttr      = [4]byte{0, 0, 0, 0x2}
	ChangeIPAndPortAttr = [4]byte{0, 0, 0, 0x6}
)

// Message Header
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0 0|     STUN Message Type     |         Message Length        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Magic Cookie                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                     Transaction ID (96 bits)                  |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type Header [20]byte

// Type of message
func (h *Header) Type() uint16 {
	return binary.BigEndian.Uint16(h[:2])
}

// Length of message
func (h *Header) Length() int {
	return int(binary.BigEndian.Uint16(h[2:4]))
}

// Transaction id including magic cookie
func (h *Header) Transaction() []byte {
	return h[4:20]
}

func (h *Header) SetLength(length uint16) {
	binary.BigEndian.PutUint16(h[2:4], length)
}

func (h *Header) SetType(typ uint16) {
	binary.BigEndian.PutUint16(h[:2], typ)
}

// NewHeader creates a new Header with transaction setting proper.
func NewHeader() Header {
	var h Header
	copy(h[4:8], MagicCookie[:])
	rand.Read(h[8:20])
	return h
}

type AttrHeader [4]byte

func (ah AttrHeader) Type() int {
	i := binary.BigEndian.Uint16(ah[:2])
	return int(i)
}

func (ah AttrHeader) Length() int {
	i := binary.BigEndian.Uint16(ah[2:4])
	return int(i)
}

type Attribute struct {
	Type  int
	Value []byte
}

func (a Attribute) Bytes() []byte {
	data := make([]byte, len(a.Value)+4)
	binary.BigEndian.PutUint16(data[:2], uint16(a.Type))
	binary.BigEndian.PutUint16(data[2:4], uint16(len(a.Value)))
	copy(data[4:], a.Value)
	return data
}

func copybytes(d []byte) []byte {
	a := make([]byte, len(d))
	copy(a, d)
	return a
}

func parseAttribute(data []byte) (int, Attribute) {
	if len(data) < 4 {
		return 0, Attribute{}
	}
	typ := binary.BigEndian.Uint16(data[:2])
	length := binary.BigEndian.Uint16(data[2:4])
	n := int(length) + 4
	if len(data) < n {
		return 0, Attribute{}
	}
	return n, Attribute{
		Type:  int(typ),
		Value: copybytes(data[4:n]),
	}
}

const (
	ipv4Family = 0x01
	ipv6Family = 0x02
)

func xor(a, b []byte) []byte {
	r := make([]byte, len(a))
	for i := range a {
		r[i] = a[i] ^ b[i]
	}
	return r
}

func parseAddress(data []byte, xorb []byte) *net.UDPAddr {
	if len(data) < 8 {
		return nil
	}
	var (
		family    = data[1]
		portbytes = data[2:4]
		port      uint16
		ip        []byte
	)
	if family == ipv4Family {
		ip = data[4:8]
	} else if family == ipv6Family {
		if len(data) < 20 {
			return nil
		}
		ip = data[4:20]
	} else {
		return nil
	}
	if xorb != nil {
		port = binary.BigEndian.Uint16(xor(portbytes, xorb[:2]))
		ip = xor(ip, xorb[:len(ip)])
	} else {
		port = binary.BigEndian.Uint16(portbytes)
		ip = copybytes(ip)
	}
	return &net.UDPAddr{IP: net.IP(ip), Port: int(port)}
}

func parseErrorCode(data []byte) (int, string) {
	if len(data) < 4 {
		return 0, ""
	}
	code := (int(data[2])&0x7)*100 + int(data[3])
	return code, string(data[4:])
}

func parseAttributes(data []byte) []Attribute {
	var r = make([]Attribute, 0)
	for len(data) > 0 {
		n, attr := parseAttribute(data)
		if n == 0 {
			return nil
		}
		r = append(r, attr)
	}
	return r
}

func listen(ip net.IP, port uint16) (*net.UDPConn, error) {
	return net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: int(port)})
}

const readTimeout = time.Second * 3
const writeTimeout = time.Second * 3

func sendAndRecv(conn *net.UDPConn, ip net.IP, port uint16,
	head Header, body []byte) ([]Attribute, *net.UDPAddr, error) {
	if len(body) > math.MaxUint16 {
		return nil, nil, errors.New("too big data body")
	}
	head.SetLength(uint16(len(body)))
	raw := make([]byte, len(head)+len(body))
	copy(raw, head[:])
	copy(raw[len(head):], body)
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return nil, nil, err
	}
	_, err := conn.WriteToUDP(body, &net.UDPAddr{IP: ip, Port: int(port)})
	if err != nil {
		return nil, nil, err
	}

	buf := make([]byte, 512) // it an safe udp package size, and usually contains full message.
	transaction := head.Transaction()
	for {
		if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return nil, nil, err
		}
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, nil, err
		}
		data := buf[:n]
		var h Header
		if len(data) < len(h) {
			return nil, nil, errors.New("incomplete message")
		}
		copy(h[:], data[:len(h)])
		if !bytes.Equal(h.Transaction(), transaction) {
			continue
		}
		data = data[len(h):]
		length := h.Length()
		if len(data) < length {
			return nil, nil, errors.New("incomplete message")
		}
		attrs := parseAttributes(data)
		if attrs == nil {
			return nil, nil, errors.New("parse attributes error")
		}
		return attrs, addr, nil
	}
}

type Addresses struct {
	RecvAddr         *net.UDPAddr
	ResponseAddress  *net.UDPAddr
	MappedAddress    *net.UDPAddr
	SourceAddress    *net.UDPAddr
	ChangedAddress   *net.UDPAddr
	XORMappedAddress *net.UDPAddr
	ErrorCode        int
	ErrorMessage     string
	UnknownAttrs     []Attribute
}

func sendBindRequest(conn *net.UDPConn, ip net.IP, port uint16, sendattrs []Attribute) (*Addresses, error) {
	var head Header
	head.SetType(BindingRequest)
	var data []byte
	for _, a := range sendattrs {
		data = append(data, a.Bytes()...)
	}
	attrs, addr, err := sendAndRecv(conn, ip, port, head, data)
	if err != nil {
		return nil, err
	}
	var addrs Addresses
	addrs.RecvAddr = addr
	for _, a := range attrs {
		switch a.Type {
		case MappedAddress:
			addrs.MappedAddress = parseAddress(a.Value, nil)
		case SourceAddress:
			addrs.SourceAddress = parseAddress(a.Value, nil)
		case ChangedAddress:
			addrs.ChangedAddress = parseAddress(a.Value, nil)
		case ResponseAddress:
			addrs.ResponseAddress = parseAddress(a.Value, nil)
		case XORMappedAddress:
			addrs.XORMappedAddress = parseAddress(a.Value, head.Transaction())
		default:
			addrs.UnknownAttrs = append(addrs.UnknownAttrs, a)
		}
	}
	return &addrs, nil
}

func natTypeByRFC3489(localhost net.IP, localport uint16, stunhost net.IP, stunport uint16) {

}
