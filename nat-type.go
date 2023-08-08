package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strings"
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
	Software          = 0x8022
	ResponseOrigin    = 0x802b
	OtherAddress      = 0x802c
)

const MagicCookie = 0x2112A442

var (
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
	binary.BigEndian.PutUint32(h[4:8], MagicCookie)
	rand.Read(h[8:20])
	return h
}

var defaultHeader = NewHeader()

func GetHeader() Header {
	return defaultHeader
}

// Attribute of message
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Type                  |            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Value (variable)                ....
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type Attribute struct {
	Type  int
	Value []byte
}

func align4(n int) int {
	return (n + 3) & 0xfffc
}

func (a Attribute) Bytes() []byte {
	n := align4(len(a.Value))
	data := make([]byte, n+4)
	binary.BigEndian.PutUint16(data[:2], uint16(a.Type))
	binary.BigEndian.PutUint16(data[2:4], uint16(n))
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
	alignlen := align4(int(length))
	n := alignlen + 4
	if len(data) < n {
		return 0, Attribute{}
	}
	return n, Attribute{
		Type:  int(typ),
		Value: copybytes(data[4:length]),
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

func listen() (*net.UDPConn, error) {
	return net.ListenUDP("udp", nil)
}

func sendAndRecv(conn *net.UDPConn, stun *net.UDPAddr,
	head Header, body []byte, timeout time.Duration) ([]Attribute, *net.UDPAddr, error) {
	if len(body) > math.MaxUint16 {
		return nil, nil, errors.New("too big data body")
	}
	head.SetLength(uint16(len(body)))
	raw := make([]byte, len(head)+len(body))
	copy(raw, head[:])
	copy(raw[len(head):], body)
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, fmt.Errorf("set sendto timeout: %w", err)
	}
	fmt.Println(raw)
	n, err := conn.WriteToUDP(raw, stun)
	if err != nil {
		return nil, nil, fmt.Errorf("sendto: %w", err)
	}
	if n != len(raw) {
		return nil, nil, fmt.Errorf("sendto incomplete: %d != %d", n, len(raw))
	}

	buf := make([]byte, 2048) // it an safe udp package size, and usually contains full message.
	transaction := head.Transaction()
	for {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, nil, fmt.Errorf("set recvfrom timeout: %w", err)
		}
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("recvfrom: %w", err)
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

func sendBindRequest(conn *net.UDPConn, stun *net.UDPAddr, sendattrs []Attribute) (*Addresses, error) {
	head := GetHeader()
	head.SetType(BindingRequest)
	var data []byte
	sendattrs = append(sendattrs, Attribute{
		Type:  Software,
		Value: []byte(`Nat-Type`),
	})
	for _, a := range sendattrs {
		data = append(data, a.Bytes()...)
	}
	var (
		attrs []Attribute
		addr  *net.UDPAddr
		err   error
	)
	// RFC 3489: Clients SHOULD retransmit the request starting with an interval
	// of 100ms, doubling every retransmit until the interval reaches 1.6s.
	// Retransmissions continue with intervals of 1.6s until a response is
	// received, or a total of 9 requests have been sent.
	var timeout = time.Millisecond * 100
	const maxTimeout = time.Second + time.Millisecond*600 // 1.6s
	for i := 0; i < 9; i++ {
		attrs, addr, err = sendAndRecv(conn, stun, head, data, timeout)
		if err != nil {
			timeout *= 2
			if timeout > maxTimeout {
				timeout = maxTimeout
			}
			continue
		}
		break
	}
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

type NatType struct {
	Addrs *Addresses
}

func (nt *NatType) String() string {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(nt)
	return buf.String()
}

func getNATTypeByRFC3489(stun *net.UDPAddr) (*NatType, error) {
	sock, err := listen()
	if err != nil {
		return nil, err
	}
	defer sock.Close()
	addrs, err := sendBindRequest(sock, stun, nil)
	if err != nil {
		return nil, err
	}
	var nt NatType
	nt.Addrs = addrs
	return &nt, nil
}

func getInternalIPv4() net.IP {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 1})
	if err != nil {
		return nil
	}
	return conn.LocalAddr().(*net.UDPAddr).IP
}

var googleIPv6 = net.ParseIP("2001:4860:4860::8888")

func getInternalIPv6() net.IP {
	conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: googleIPv6, Port: 1})
	if err != nil {
		return nil
	}
	return conn.LocalAddr().(*net.UDPAddr).IP
}

func main() {
	stun, err := net.ResolveUDPAddr("udp4", "stun.ekiga.net:3478")
	if err != nil {
		panic(err)
	}
	nt, err := getNATTypeByRFC3489(stun)
	if err != nil {
		panic(err)
	}
	fmt.Println(nt)
}
