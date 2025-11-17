package main

import (
	"bytes"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/logger"
	"github.com/negasus/haproxy-spoe-go/request"

	"github.com/mrheinen/p0fclient"
)

/*
Build:
  go mod init example.com/spoa-p0f
  go get github.com/negasus/haproxy-spoe-go@v1.0.7
  go get github.com/mrheinen/p0fclient@latest
  go build -o spoa-p0f .

Service listens on 127.0.0.1:9000
*/

const (
	listenAddr = "127.0.0.1:9000" // SPOE TCP listener
	p0fSock    = "/var/run/p0f.sock"  //agent sends queries to this p0f socket 
	cacheTTL   = 30 * time.Second  // short agent cache to handle multiple requests
)

// cache entry for last p0f result per source IP
type cacheEntry struct {
	at           time.Time
	os, link     string
	dist, uptime int
}

var (
	pc       *p0fclient.P0fClient
	cacheMu  sync.Mutex
	ipCache  = map[string]cacheEntry{}
	onceConn sync.Once
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
	c := p0fclient.NewP0fClient(p0fSock)
	if err := c.Connect(); err != nil {
		return err
	}
	pc = c
	return nil
}

func queryP0F(ip net.IP) (osName, link string, dist, uptime int, ok bool) {
	if ip == nil {
		return
	}
	key := ip.String()

	// cache first
	cacheMu.Lock()
	if e, hit := ipCache[key]; hit && time.Since(e.at) < cacheTTL {
		cacheMu.Unlock()
		return e.os, e.link, e.dist, e.uptime, true
	}
	cacheMu.Unlock()

	// (re)connect lazily
	if err := ensureP0F(); err != nil {
		log.Printf("p0f connect error: %v", err)
		return
	}

	resp, err := pc.QueryIP(ip)
	if err != nil || resp == nil || resp.Status == 0x20 {
		if err != nil {
			log.Printf("p0f query error for %s: %v", ip, err)
		}
		return
	}

	// map fields
	osName = btrim(resp.OsName[:])
	if flv := btrim(resp.OsFlavor[:]); flv != "" {
		if osName == "" {
			osName = flv
		} else {
			osName = osName + " " + flv
		}
	}
	link = btrim(resp.LinkType[:])
	dist = int(resp.Distance)
	uptime = int(resp.UptimeMinutes)

	// cache
	cacheMu.Lock()
	ipCache[key] = cacheEntry{
		at:     time.Now(),
		os:     osName,
		link:   link,
		dist:   dist,
		uptime: uptime,
	}
	cacheMu.Unlock()

	return osName, link, dist, uptime, true
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

	// Ensure p0f socket/client
	if err := ensureP0F(); err != nil {
		log.Printf("p0f connect error: %v", err)
		return
	}

	// Query p0f for this IP
	resp, err := pc.QueryIP(srcIP)
	if err != nil || resp == nil || resp.Status == 0x20 { // 0x20 = P0F_STATUS_NOMATCH
		if err != nil {
			log.Printf("p0f query error for %s: %v", srcIP, err)
		} else {
			log.Printf("p0f: no match for %s", srcIP)
		}
		return
	}

	// -------- parse fields --------
	osName := btrim(resp.OsName[:])
	osFlv  := btrim(resp.OsFlavor[:])
	if osFlv != "" {
		if osName == "" {
			osName = osFlv
		} else {
			osName = osName + " " + osFlv
		}
	}
	link    := btrim(resp.LinkType[:])
	httpNam := btrim(resp.HttpName[:])
	httpFlv := btrim(resp.HttpFlavor[:])
	lang    := btrim(resp.Language[:])

	dist      := int(resp.Distance)
	uptime    := int(resp.UptimeMinutes)
	osMatchQ  := int(resp.OsMatchQ)
	badSW     := resp.BadSw != 0
	firstSeen := int(resp.FirstSeen)
	lastSeen  := int(resp.LastSeen)
	totalConn := int(resp.TotalCount)
	lastNat   := int(resp.LastNat)
	lastChg   := int(resp.LastChg)
	upModDays := int(resp.UpModDays)

	// NAT heuristic at IP level: NAT seen "recently" relative to lastSeen (<= 1h)
	nat := ""
	if lastNat > 0 && lastSeen > 0 && (lastSeen-lastNat) <= 3600 {
		nat = "1" // or "recent"
	}

	// -------- set HAProxy session vars (UNPREFIXED KEYS!) --------
	if osName   != "" { setSessVar(req, "os", osName) }
	if link     != "" { setSessVar(req, "link", link) }
	if dist     != 0  { setSessVar(req, "dist", dist) }
	if uptime   >  0  { setSessVar(req, "uptime", uptime) }
	if nat      != "" { setSessVar(req, "nat", nat) }

	if osMatchQ >  0  { setSessVar(req, "os_match_q", osMatchQ) }
	if badSW           { setSessVar(req, "bad_sw", "1") }

	if httpNam  != "" { setSessVar(req, "http_name",   httpNam) }
	if httpFlv  != "" { setSessVar(req, "http_flavor", httpFlv) }
	if lang     != "" { setSessVar(req, "language",    lang) }

	if firstSeen>  0  { setSessVar(req, "first_seen",  firstSeen) }
	if lastSeen >  0  { setSessVar(req, "last_seen",   lastSeen) }
	if totalConn> 0   { setSessVar(req, "total_conn",  totalConn) }
	if lastNat  >  0  { setSessVar(req, "last_nat",    lastNat) }
	if lastChg  >  0  { setSessVar(req, "last_chg",    lastChg) }
	if upModDays> 0   { setSessVar(req, "up_mod_days", upModDays) }

	log.Printf("p0f OK %s os=%q link=%q dist=%d uptime=%d nat=%s matchQ=%d",
		srcIP, osName, link, dist, uptime, nat, osMatchQ)
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

