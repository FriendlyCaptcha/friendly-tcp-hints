package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/logger"
	"github.com/negasus/haproxy-spoe-go/request"
)

/*
Build:
  go mod init example.com/spoa-p0f
  go get github.com/negasus/haproxy-spoe-go@v1.0.7
  go build -o spoa-p0f .

Service listens on 127.0.0.1:9000
*/

const (
	listenAddr = "127.0.0.1:9000"    // SPOE TCP listener
	p0fSock    = "/var/run/p0f.sock" //agent sends queries to this p0f socket
	cacheTTL   = 30 * time.Second    // short agent cache to handle multiple requests
)

const (
	p0fStatusBadQuery = 0x00
	p0fStatusOK       = 0x10
	p0fStatusNoMatch  = 0x20
	p0fAddrIPv4       = 0x04
	p0fAddrIPv6       = 0x06
	p0fMatchFuzzy     = 0x01
	p0fMatchGeneric   = 0x02
	p0fRequestMagic   = 0x50304601
	p0fResponseMagic  = 0x50304602
)

type p0fQuery struct {
	Magic       uint32
	AddressType uint8
	Address     [16]uint8
}

type p0fResponse struct {
	Magic         uint32
	Status        uint32
	FirstSeen     uint32
	LastSeen      uint32
	TotalCount    uint32
	UptimeMinutes uint32
	UpModDays     uint32
	LastNat       uint32
	LastChg       uint32
	Distance      int16
	BadSw         uint8
	OsMatchQ      uint8
	OsName        [32]uint8
	OsFlavor      [32]uint8
	HttpName      [32]uint8
	HttpFlavor    [32]uint8
	LinkMtu       uint16
	LinkMss       uint16
	LinkType      [32]uint8
	Language      [32]uint8
}

type p0fClient struct {
	socket string
	conn   net.Conn
	mu     sync.Mutex
}

func newP0fClient(socket string) *p0fClient {
	return &p0fClient{socket: socket}
}

func (p *p0fClient) Connect() error {
	if _, err := os.Stat(p.socket); err != nil {
		return fmt.Errorf("could not stat socket: %w", err)
	}
	conn, err := net.Dial("unix", p.socket)
	if err != nil {
		return fmt.Errorf("could not open socket: %w", err)
	}
	p.conn = conn
	return nil
}

func (p *p0fClient) ensureConn() error {
	if p == nil {
		return fmt.Errorf("p0f client not initialized")
	}
	if p.conn != nil {
		return nil
	}
	return p.Connect()
}

func (p *p0fClient) QueryIP(ip net.IP) (*p0fResponse, error) {
	if err := p.ensureConn(); err != nil {
		return nil, err
	}
	query, err := createQuery(ip)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, query); err != nil {
		return nil, fmt.Errorf("encode query: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.conn.Write(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("write query: %w", err)
	}
	resp := &p0fResponse{}
	respSize := binary.Size(resp)
	readBuf := make([]byte, respSize)
	if _, err := io.ReadFull(p.conn, readBuf); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if err := binary.Read(bytes.NewReader(readBuf), binary.LittleEndian, resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if resp.Magic != p0fResponseMagic {
		return nil, fmt.Errorf("unexpected response magic 0x%x", resp.Magic)
	}
	switch resp.Status {
	case p0fStatusOK, p0fStatusNoMatch:
		return resp, nil
	case p0fStatusBadQuery:
		return nil, fmt.Errorf("p0f bad query")
	default:
		return nil, fmt.Errorf("unknown p0f status 0x%x", resp.Status)
	}
}

func createQuery(ip net.IP) (p0fQuery, error) {
	q := p0fQuery{Magic: p0fRequestMagic}
	if ipv4 := ip.To4(); ipv4 != nil {
		q.AddressType = p0fAddrIPv4
		copy(q.Address[:], ipv4)
		return q, nil
	}
	if ipv6 := ip.To16(); ipv6 != nil {
		q.AddressType = p0fAddrIPv6
		copy(q.Address[:], ipv6)
		return q, nil
	}
	return q, fmt.Errorf("invalid IP address")
}

// cache entry for last p0f result per source IP
type cacheEntry struct {
	at   time.Time
	resp *p0fResponse
}

var (
	pc      *p0fClient
	cacheMu sync.Mutex
	ipCache = map[string]cacheEntry{}
)

// --- helpers ---

func btrim(b []byte) string {
	// p0f strings are fixed-size byte arrays; trim trailing NUL/space/newline
	return string(bytes.TrimRight(b, "\x00 \t\r\n"))
}

func setSessVar(req *request.Request, key string, val interface{}) {
	req.Actions.SetVar(action.ScopeSession, key, val)
}

func ensureP0F() error {
	if pc != nil {
		return nil
	}
	c := newP0fClient(p0fSock)
	if err := c.Connect(); err != nil {
		return err
	}
	pc = c
	return nil
}

func queryP0F(ip net.IP) (*p0fResponse, error) {
	if ip == nil {
		return nil, nil
	}
	key := ip.String()

	cacheMu.Lock()
	if e, hit := ipCache[key]; hit && time.Since(e.at) < cacheTTL {
		cacheMu.Unlock()
		return e.resp, nil
	}
	cacheMu.Unlock()

	if err := ensureP0F(); err != nil {
		return nil, err
	}

	resp, err := pc.QueryIP(ip)
	if err != nil {
		return nil, err
	}

	if resp.Status == p0fStatusOK {
		cacheMu.Lock()
		copyResp := *resp
		ipCache[key] = cacheEntry{at: time.Now(), resp: &copyResp}
		cacheMu.Unlock()
	}

	return resp, nil
}

// p0f response handler
func handle(req *request.Request) {
	// Get the message declared in .spop: "p0f-conn"
	msg, err := req.Messages.GetByName("p0f-conn")
	if err != nil {
		return
	}

	// Extract client IP from args: "ci"
	var srcIP net.IP
	if v, ok := msg.KV.Get("ci"); ok {
		switch t := v.(type) {
		case net.IP:
			srcIP = t
		case string:
			srcIP = net.ParseIP(t)
		}
	}
	if srcIP == nil {
		return
	}

	resp, err := queryP0F(srcIP)
	if err != nil {
		log.Printf("p0f query error for %s: %v", srcIP, err)
		return
	}
	if resp == nil || resp.Status == p0fStatusNoMatch {
		log.Printf("p0f: no match for %s", srcIP)
		return
	}

	// -------- parse fields --------
	osName := btrim(resp.OsName[:])
	osFlv := btrim(resp.OsFlavor[:])
	if osFlv != "" {
		if osName == "" {
			osName = osFlv
		} else {
			osName = osName + " " + osFlv
		}
	}
	link := btrim(resp.LinkType[:])
	linkMTU := int(resp.LinkMtu)
	linkMSS := int(resp.LinkMss)
	httpNam := btrim(resp.HttpName[:])
	httpFlv := btrim(resp.HttpFlavor[:])
	lang := btrim(resp.Language[:])

	dist := int(resp.Distance)
	uptime := int(resp.UptimeMinutes)
	osMatchQ := int(resp.OsMatchQ)
	badSW := resp.BadSw != 0
	firstSeen := int(resp.FirstSeen)
	lastSeen := int(resp.LastSeen)
	totalConn := int(resp.TotalCount)
	lastNat := int(resp.LastNat)
	lastChg := int(resp.LastChg)
	upModDays := int(resp.UpModDays)

	// NAT heuristic at IP level: NAT seen "recently" relative to lastSeen (<= 1h)
	nat := ""
	if lastNat > 0 && lastSeen > 0 && (lastSeen-lastNat) <= 3600 {
		nat = "1" // or "recent"
	}

	// -------- set HAProxy session vars (UNPREFIXED KEYS!) --------
	if osName != "" {
		setSessVar(req, "os", osName)
	}
	if link != "" {
		setSessVar(req, "link", link)
	}
	if linkMTU > 0 {
		setSessVar(req, "link_mtu", linkMTU)
	}
	if linkMSS > 0 {
		setSessVar(req, "link_mss", linkMSS)
	}
	if dist != 0 {
		setSessVar(req, "dist", dist)
	}
	if uptime > 0 {
		setSessVar(req, "uptime", uptime)
	}
	if nat != "" {
		setSessVar(req, "nat", nat)
	}

	if osMatchQ > 0 {
		setSessVar(req, "os_match_q", osMatchQ)
	}
	if badSW {
		setSessVar(req, "bad_sw", "1")
	}

	if httpNam != "" {
		setSessVar(req, "http_name", httpNam)
	}
	if httpFlv != "" {
		setSessVar(req, "http_flavor", httpFlv)
	}
	if lang != "" {
		setSessVar(req, "language", lang)
	}

	if firstSeen > 0 {
		setSessVar(req, "first_seen", firstSeen)
	}
	if lastSeen > 0 {
		setSessVar(req, "last_seen", lastSeen)
	}
	if totalConn > 0 {
		setSessVar(req, "total_conn", totalConn)
	}
	if lastNat > 0 {
		setSessVar(req, "last_nat", lastNat)
	}
	if lastChg > 0 {
		setSessVar(req, "last_chg", lastChg)
	}
	if upModDays > 0 {
		setSessVar(req, "up_mod_days", upModDays)
	}

	log.Printf("p0f OK %s os=%q link=%q mtu=%d mss=%d dist=%d uptime=%d nat=%s matchQ=%d",
		srcIP, osName, link, linkMTU, linkMSS, dist, uptime, nat, osMatchQ)
}

func main() {
	// Warn early if socket not present (doesn't abort; agent still serves)
	if _, err := os.Stat(p0fSock); err != nil {
		log.Printf("warning: p0f socket %s not accessible yet: %v", p0fSock, err)
	}

	// Listen for HAProxy SPOE connections
	l, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		log.Fatalf("listen %s failed: %v", listenAddr, err)
	}
	log.Printf("SPOE agent listening on %s", listenAddr)
	defer l.Close()

	a := agent.New(handle, logger.NewDefaultLog())
	if err := a.Serve(l); err != nil {
		log.Fatalf("agent serve error: %v", err)
	}
}
