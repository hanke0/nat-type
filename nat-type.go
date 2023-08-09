package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"strconv"
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
	verbose2.Printf("attribute length %d", len(data))
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

func sendAndRecv(conn *net.UDPConn, head Header, body []byte, timeout time.Duration) ([]Attribute, *net.UDPAddr, error) {
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
	n, err := conn.Write(raw)
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
		verbose2.Printf("message type 0x%x", h.Type())
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

type Addr struct {
	*net.UDPAddr
}

func (i Addr) String() string {
	if i.UDPAddr == nil {
		return "null"
	}
	return fmt.Sprintf("%s:%d", i.IP, i.Port)
}

func (i Addr) MarshalText() ([]byte, error) {
	return []byte(i.String()), nil
}

func (i Addr) UnmarshalText(text []byte) error {
	addr, err := net.ResolveUDPAddr("udp", string(text))
	if err != nil {
		return err
	}
	i.UDPAddr = addr
	return nil
}

type Addresses struct {
	MappedAddress    Addr
	SourceAddress    Addr
	ChangedAddress   Addr
	XORMappedAddress Addr
	ResponseOrigin   Addr
	ErrorCode        int
	ErrorMessage     string
	Software         string
	UnknownAttrs     []Attribute
}

func (a *Addresses) String() string {
	return stringify(a)
}

func (a *Addresses) GetMappedAddress() *net.UDPAddr {
	if a.XORMappedAddress.UDPAddr != nil {
		return a.XORMappedAddress.UDPAddr
	}
	return a.MappedAddress.UDPAddr
}

func (a *Addresses) GetSourceAddress() *net.UDPAddr {
	return a.SourceAddress.UDPAddr
}

func (a *Addresses) GetChangedAddress() *net.UDPAddr {
	return a.ChangedAddress.UDPAddr
}

func (a *Addresses) GetError() error {
	if a.ErrorCode != 0 {
		return fmt.Errorf("%d %s", a.ErrorCode, a.ErrorMessage)
	}
	return nil
}

func sendBindRequest(conn *net.UDPConn, stun *net.UDPAddr, changeIP, changePort bool) (*Addresses, error) {
	head := GetHeader()
	head.SetType(BindingRequest)
	var data []byte
	sendattrs := []Attribute{
		{Type: Software, Value: []byte(`stun`)},
	}
	if changeIP && changePort {
		sendattrs = append(sendattrs, Attribute{
			Type:  ChangeRequest,
			Value: ChangeIPAndPortAttr[:],
		})
	} else if changeIP {
		sendattrs = append(sendattrs, Attribute{
			Type:  ChangeRequest,
			Value: ChangeIPAttr[:],
		})
	} else if changePort {
		sendattrs = append(sendattrs, Attribute{
			Type:  ChangedAddress,
			Value: ChangePortAttr[:],
		})
	}
	for _, a := range sendattrs {
		data = append(data, a.Bytes()...)
	}
	var (
		attrs []Attribute
		err   error
	)
	// RFC 3489: Clients SHOULD retransmit the request starting with an interval
	// of 100ms, doubling every retransmit until the interval reaches 1.6s.
	// Retransmissions continue with intervals of 1.6s until a response is
	// received, or a total of 9 requests have been sent.
	var timeout = time.Millisecond * 100
	const maxTimeout = time.Second + time.Millisecond*600 // 1.6s
	for i := 0; i < 9; i++ {
		attrs, _, err = sendAndRecv(conn, head, data, timeout)
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
	for _, a := range attrs {
		switch a.Type {
		case MappedAddress:
			addrs.MappedAddress = Addr{a.GetAddress(nil)}
		case SourceAddress:
			addrs.SourceAddress = Addr{a.GetAddress(nil)}
		case ChangedAddress, OtherAddress:
			// describe rfc5780, other address is a rename of changed address
			addrs.ChangedAddress = Addr{a.GetAddress(nil)}
		case XORMappedAddress, XORMappedAddressNonStd:
			addrs.XORMappedAddress = Addr{a.GetAddress(head.Transaction())}
		case ResponseOrigin:
			addrs.ResponseOrigin = Addr{a.GetAddress(nil)}
		case ErrorCode:
			code, msg := a.GetErrorCode()
			addrs.ErrorCode = code
			addrs.ErrorMessage = msg
		case Software:
			addrs.Software = a.GetString()
		default:
			addrs.UnknownAttrs = append(addrs.UnknownAttrs, a)
		}
	}
	return &addrs, nil
}

const (
	OpenInternet          = "On the open Internet"
	FirewallBlockUDP      = "Firewall that blocks UDP"
	SymmetricUDPFirewall  = "symmetric UDP Firewall"
	FullConeNAT           = "Full-cone NAT"
	SymmetricNAT          = "Symmetric NAT"
	RestrictedConeNAT     = "Restricted cone NAT"
	RestrictedPortConeNAT = "Restricted port cone NAT"
)

type NatType struct {
	Mapped         Addr
	Internal       Addr
	ResponseOrigin Addr
	Topology       string
}

func (nt *NatType) String() string {
	return stringify(nt)
}

// getNATTypeByRFC3489 gets NAT type as describe in rfc3489
//
//	                     +--------+
//	                     |  Test  |
//	                     |   I    |
//	                     +--------+
//	                          |
//	                          |
//	                          V
//	                         /\              /\
//	                      N /  \ Y          /  \ Y             +--------+
//	       UDP     <-------/Resp\--------->/ IP \------------->|  Test  |
//	       Blocked         \ ?  /          \Same/              |   II   |
//	                        \  /            \? /               +--------+
//	                         \/              \/                    |
//	                                          | N                  |
//	                                          |                    V
//	                                          V                    /\
//	                                      +--------+  Sym.      N /  \
//	                                      |  Test  |  UDP    <---/Resp\
//	                                      |   II   |  Firewall   \ ?  /
//	                                      +--------+              \  /
//	                                          |                    \/
//	                                          V                     |Y
//	               /\                         /\                    |
//	Symmetric  N  /  \       +--------+   N  /  \                   V
//	   NAT  <--- / IP \<-----|  Test  |<--- /Resp\               Open
//	             \Same/      |   I    |     \ ?  /               Internet
//	              \? /       +--------+      \  /
//	               \/                         \/
//	               |                           |Y
//	               |                           |
//	               |                           V
//	               |                           Full
//	               |                           Cone
//	               V              /\
//	           +--------+        /  \ Y
//	           |  Test  |------>/Resp\---->Restricted
//	           |   III  |       \ ?  /
//	           +--------+        \  /
//	                              \/
//	                               |N
//	                               |       Port
//	                               +------>Restricted
//
// In test I, the client sends a
// STUN Binding Request to a server, without any flags set in the
// CHANGE-REQUEST attribute, and without the RESPONSE-ADDRESS attribute.
// This causes the server to send the response back to the address and
// port that the request came from.
// In test II, the client sends a
// Binding Request with both the "change IP" and "change port" flags
// from the CHANGE-REQUEST attribute set.
// In test III, the client sends
// a Binding Request with only the "change port" flag set.
func getNATTypeByRFC3489(stun *net.UDPAddr) (*NatType, error) {
	sock, err := net.DialUDP("udp", nil, stun)
	if err != nil {
		return nil, err
	}
	defer sock.Close()
	var nt NatType
	nt.Internal = Addr{sock.LocalAddr().(*net.UDPAddr)}

	verbose1.Printf("test1 request: %s -> %s", sock.LocalAddr(), stun)
	addrs1, err := sendBindRequest(sock, stun, false, false)
	verbose1.Printf("test1 response: %v, %s", err, addrs1)
	if err != nil {
		return nil, err
	}
	if err := addrs1.GetError(); err != nil {
		return nil, err
	}
	mapped := addrs1.GetMappedAddress()
	if mapped == nil {
		return &nt, nil
	}
	if err := checkSourceAddress(addrs1, stun); err != nil {
		return nil, err
	}
	nt.ResponseOrigin = addrs1.ResponseOrigin

	test1same := addrEqual(addrs1.GetMappedAddress(), nt.Internal.UDPAddr)
	verbose1.Printf("test2 request: %s -> %s", sock.LocalAddr(), stun)
	addrs2, err := sendBindRequest(sock, stun, true, true)
	verbose1.Printf("test2 rsponse: %v, %s", err, addrs2)

	if test1same {
		if err != nil || addrs2.GetError() != nil {
			nt.Mapped = Addr{mapped}
			nt.Topology = SymmetricUDPFirewall
			return &nt, nil
		}
		nt.Mapped = Addr{mapped}
		nt.Topology = OpenInternet
		return &nt, nil
	}
	if err == nil && addrs2.GetError() == nil {
		nt.Mapped = Addr{mapped}
		nt.Topology = FullConeNAT
		return &nt, nil
	}
	changed := addrs1.GetChangedAddress()
	if changed == nil {
		return nil, fmt.Errorf("response error: response without changed address")
	}
	verbose1.Printf("test1-1 request: %s -> %s", sock.LocalAddr(), changed)
	addrs3, err := sendBindRequest(sock, changed, false, false)
	verbose1.Printf("test1-1 response: %v, %s", err, addrs3)
	if err != nil {
		return nil, err
	}
	if addrs3.GetError() != nil {
		return nil, addrs3.GetError()
	}
	if !addrEqual(addrs3.GetMappedAddress(), mapped) {
		nt.Mapped = Addr{mapped}
		nt.Topology = SymmetricNAT
		return &nt, nil
	}
	verbose1.Printf("test3 request: %s -> %s", sock.LocalAddr(), changed)
	addrs4, err := sendBindRequest(sock, changed, false, true)
	verbose1.Printf("test3 request: %v, %s", err, addrs4)
	if err == nil && addrs4.GetError() == nil {
		nt.Mapped = Addr{mapped}
		nt.Topology = RestrictedConeNAT
		return &nt, nil
	}
	nt.Mapped = Addr{mapped}
	nt.Topology = RestrictedPortConeNAT
	return &nt, nil
}

func checkSourceAddress(addrs *Addresses, stun *net.UDPAddr) error {
	if source := addrs.GetSourceAddress(); source != nil {
		if !addrEqual(source, stun) {
			return errors.New("server error: bad response IP/port")
		}
	}
	return nil
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

func stringify(a interface{}) string {
	if a == nil {
		return "null"
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(a)
	return buf.String()
}

func addrEqual(a, b *net.UDPAddr) bool {
	return bytes.Equal(a.IP, b.IP) && a.Port == b.Port
}

type Option struct {
	Servers   string
	IPv4      bool
	IPv6      bool
	NoDefault bool
	Verbose   flagCount
}

type flagCount int

func (f flagCount) String() string {
	return strconv.Itoa(int(f))
}

func (f flagCount) IsBoolFlag() bool {
	return true
}

func (f *flagCount) Set(s string) error {
	*f++
	return nil
}

func (o *Option) Parse() {
	flag.StringVar(&o.Servers, "a", "", "stun servers(hostname:port), multi server split by ,")
	flag.BoolVar(&o.IPv4, "4", false, "test IPv4")
	flag.BoolVar(&o.IPv6, "6", true, "test IPv6")
	flag.BoolVar(&o.NoDefault, "nodefault", false, "disable default stun servers")
	flag.Var(&o.Verbose, "v", "set verbose mode")
	flag.Parse()
}

var defaultStunServers = []string{
	"stun.qq.com:3478",
	"stun.miwifi.com:3478",
	"stun.ekiga.net:3478",
	"stun1.l.google.com:19302",
}

func natTypeTest(family, address string) (*NatType, error) {
	stun, err := net.ResolveUDPAddr(family, address)
	if err != nil {
		return nil, err
	}
	return getNATTypeByRFC3489(stun)
}

type Result struct {
	Stun    string
	NatType *NatType
	Error   error
}

func main() {
	var opt Option
	opt.Parse()
	family := "udp"
	if opt.IPv6 {
		family = "udp6"
	}
	if opt.IPv4 {
		family = "udp4"
	}
	if opt.Verbose < 2 {
		verbose2.SetOutput(io.Discard)
	}
	if opt.Verbose < 1 {
		verbose1.SetOutput(io.Discard)
	}
	var servers []string
	if !opt.NoDefault {
		servers = append(servers, defaultStunServers...)
	}
	lists := strings.Split(opt.Servers, ",")
	for _, i := range lists {
		i = strings.TrimSpace(i)
		if i != "" {
			servers = append(servers, i)
		}
	}
	var result []Result
	for _, s := range servers {
		verbose1.Printf("stun test begin: %s", s)
		nt, err := natTypeTest(family, s)
		result = append(result, Result{Stun: s, NatType: nt, Error: err})
		verbose1.Printf("stun test finish: %s", s)
	}
	for _, r := range result {
		log.Printf("%s", r.Stun)
		if r.Error != nil {
			log.Printf("\tError:\t%v", r.Error)
		} else {
			log.Printf("\tInternal:\t%s\n\tExternal:\t%s\n\tNAT-Type:\t%s",
				r.NatType.Internal, r.NatType.Mapped, r.NatType.Topology)
		}
	}
}
