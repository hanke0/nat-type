package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

var (
	verbose1 = log.New(os.Stderr, "", 0)
	verbose2 = log.New(os.Stderr, "", 0)
)

func init() {
	log.SetFlags(0)
	log.SetOutput(os.Stderr)
	rand.Seed(time.Now().UnixNano())
}

// Message Types
// describe in
//
//	https://www.rfc-editor.org/rfc/rfc3489.html#section-11.1
//	https://www.rfc-editor.org/rfc/rfc5389.html#section-6
const (
	BindingRequest            = 0x0001
	BindingResponse           = 0x0101
	BindingErrorResponse      = 0x0111
	SharedSecretRequest       = 0x0002
	SharedSecretResponse      = 0x0102
	SharedSecretErrorResponse = 0x0112
)

// Attributes Types
// describe in
//
//	https://www.rfc-editor.org/rfc/rfc5389.html#section-18.2
//	https://www.rfc-editor.org/rfc/rfc3489.html#section-11.2
//	https://www.rfc-editor.org/rfc/rfc5780.html#section-7
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
	REALM             = 0x0014
	NONCE             = 0x0015
	XORMappedAddress  = 0x0020
	Padding           = 0x0026
	ResponsePort      = 0x0027
	Software          = 0x8022
	AlternateServer   = 0x8023
	Fingerprint       = 0x8028
	ResponseOrigin    = 0x802b
	OtherAddress      = 0x802c

	// Non-Standard
	XORMappedAddressNonStd = 0x8020
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

func parseAttribute(data []byte) (int, Attribute) {
	if len(data) < 4 {
		return 0, Attribute{}
	}
	typ := binary.BigEndian.Uint16(data[:2])
	length := binary.BigEndian.Uint16(data[2:4])
	alignlen := align4(int(length))
	verbose2.Printf("attribute 0x%x {%d}%v", typ, length, data[4:length+4])
	n := alignlen + 4
	if len(data) < n {
		return 0, Attribute{}
	}
	return n, Attribute{
		Type:  int(typ),
		Value: copybytes(data[4 : length+4]),
	}
}

func parseAttributes(data []byte) []Attribute {
	var r = make([]Attribute, 0)
	verbose1.Printf("attribute length %d", len(data))
	for len(data) > 0 {
		n, attr := parseAttribute(data)
		verbose2.Printf("parse 1 attribute: consume=%d, total=%d", n, len(data))
		if n == 0 {
			return nil
		}
		data = data[n:]
		r = append(r, attr)
	}
	return r
}

func (a Attribute) Bytes() []byte {
	n := align4(len(a.Value))
	data := make([]byte, n+4)
	binary.BigEndian.PutUint16(data[:2], uint16(a.Type))
	binary.BigEndian.PutUint16(data[2:4], uint16(n))
	copy(data[4:], a.Value)
	return data
}

func (a Attribute) GetString() string {
	if len(a.Value) == 0 {
		return ""
	}
	if a.Value[len(a.Value)-1] == 0 {
		return string(a.Value[:len(a.Value)-1])
	}
	return string(a.Value)
}

const (
	ipv4Family = 0x01
	ipv6Family = 0x02
)

func (a *Attribute) GetAddress(xorb []byte) *net.UDPAddr {
	data := a.Value
	if len(data) < 8 {
		log.Printf("attribute address length too short: %d", len(data))
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

func (a Attribute) GetErrorCode() (int, string) {
	data := a.Value
	if len(data) < 4 {
		log.Printf("attribute ERROR-CODE length too short: %d", len(data))
		return 0, ""
	}
	code := (int(data[2])&0x7)*100 + int(data[3])
	return code, string(data[4:])
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
	verbose1.Printf("sendto %s", stun)
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
		verbose1.Printf("recvfrom %s", addr)
		data := buf[:n]
		var h Header
		if len(data) < len(h) {
			return nil, nil, errors.New("incomplete message")
		}
		copy(h[:], data[:len(h)])
		if !bytes.Equal(h.Transaction(), transaction) {
			continue
		}
		verbose1.Printf("recvfrom message type 0x%x", h.Type())
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
	RemoteAddr       *net.UDPAddr
	MappedAddress    *net.UDPAddr
	SourceAddress    *net.UDPAddr
	ChangedAddress   *net.UDPAddr
	XORMappedAddress *net.UDPAddr
	ErrorCode        int
	ErrorMessage     string
	Sofeware         string
	UnknownAttrs     []Attribute
}

func (a *Addresses) GetMappedAddress() *net.UDPAddr {
	if a.XORMappedAddress != nil {
		return a.XORMappedAddress
	}
	return a.MappedAddress
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
	addrs.RemoteAddr = addr
	for _, a := range attrs {
		switch a.Type {
		case MappedAddress:
			addrs.MappedAddress = a.GetAddress(nil)
		case SourceAddress:
			addrs.SourceAddress = a.GetAddress(nil)
		case ChangedAddress:
			addrs.ChangedAddress = a.GetAddress(nil)
		case XORMappedAddress, XORMappedAddressNonStd:
			addrs.XORMappedAddress = a.GetAddress(head.Transaction())
		case ErrorCode:
			code, msg := a.GetErrorCode()
			addrs.ErrorCode = code
			addrs.ErrorMessage = msg
		case Software:
			addrs.Sofeware = a.GetString()
		default:
			addrs.UnknownAttrs = append(addrs.UnknownAttrs, a)
		}
	}
	return &addrs, nil
}

type NatType struct {
	Addrs    *Addresses
	Internal net.IP
}

func (nt *NatType) String() string {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	enc.Encode(nt)
	return buf.String()
}

func getNATTypeByRFC3489(stun *net.UDPAddr) (*NatType, error) {
	var (
		nt  NatType
		err error
	)
	if stun.IP.To4() == nil {
		nt.Internal, err = getInternalIPv6()
	} else {
		nt.Internal, err = getInternalIPv4()
	}
	if err != nil {
		return nil, err
	}

	sock, err := listen()
	if err != nil {
		return nil, err
	}
	defer sock.Close()
	addrs, err := sendBindRequest(sock, stun, nil)
	if err != nil {
		return nil, err
	}
	nt.Addrs = addrs
	return &nt, nil
}

func getInternalIPv4() (net.IP, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 1})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}

var googleIPv6 = net.ParseIP("2001:4860:4860::8888")

func getInternalIPv6() (net.IP, error) {
	conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: googleIPv6, Port: 1})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}

func listen() (*net.UDPConn, error) {
	return net.ListenUDP("udp", nil)
}

func align4(n int) int {
	return (n + 3) & 0xfffc
}

func xor(a, b []byte) []byte {
	r := make([]byte, len(a))
	for i := range a {
		r[i] = a[i] ^ b[i]
	}
	return r
}

func copybytes(d []byte) []byte {
	a := make([]byte, len(d))
	copy(a, d)
	return a
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
