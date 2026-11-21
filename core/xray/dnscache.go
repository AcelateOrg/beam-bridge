package xray

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	dnsCacheLimit  = 8192
	dnsCacheMinTTL = time.Minute
	dnsCacheMaxTTL = time.Hour
)

// dnsCache remembers which name an address was resolved for, learned from
// the DNS answers passing through the tunnel. It names flows the core does
// not sniff (bypassed, UDP, encrypted ClientHello).
type dnsCache struct {
	mu      sync.Mutex
	entries map[netip.Addr]dnsCacheEntry
}

type dnsCacheEntry struct {
	name    string
	expires time.Time
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[netip.Addr]dnsCacheEntry)}
}

// observe records the A/AAAA answers of a DNS response under the name the
// client asked for (not the CNAME target: that is what the user knows).
func (c *dnsCache) observe(msg []byte) {
	var parser dnsmessage.Parser
	header, err := parser.Start(msg)
	if err != nil || !header.Response || header.RCode != dnsmessage.RCodeSuccess {
		return
	}
	question, err := parser.Question()
	if err != nil {
		return
	}
	name := cleanHost(question.Name.String())
	if name == "" {
		return
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return
	}

	now := time.Now()
	var addrs []netip.Addr
	var ttl uint32
	for {
		answer, err := parser.AnswerHeader()
		if err != nil {
			break
		}
		switch answer.Type {
		case dnsmessage.TypeA:
			resource, err := parser.AResource()
			if err != nil {
				return
			}
			addrs = append(addrs, netip.AddrFrom4(resource.A))
		case dnsmessage.TypeAAAA:
			resource, err := parser.AAAAResource()
			if err != nil {
				return
			}
			addrs = append(addrs, netip.AddrFrom16(resource.AAAA))
		default:
			if err := parser.SkipAnswer(); err != nil {
				return
			}
			continue
		}
		if ttl == 0 || answer.TTL < ttl {
			ttl = answer.TTL
		}
	}
	if len(addrs) == 0 {
		return
	}

	life := time.Duration(ttl) * time.Second
	life = min(max(life, dnsCacheMinTTL), dnsCacheMaxTTL)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries)+len(addrs) > dnsCacheLimit {
		for addr, entry := range c.entries {
			if now.After(entry.expires) {
				delete(c.entries, addr)
			}
		}
		if len(c.entries)+len(addrs) > dnsCacheLimit {
			c.entries = make(map[netip.Addr]dnsCacheEntry)
		}
	}
	for _, addr := range addrs {
		c.entries[addr] = dnsCacheEntry{name: name, expires: now.Add(life)}
	}
}

func (c *dnsCache) lookup(addr netip.Addr) string {
	if c == nil || !addr.IsValid() {
		return ""
	}
	addr = addr.Unmap()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[addr]
	if !ok {
		return ""
	}
	if time.Now().After(entry.expires) {
		delete(c.entries, addr)
		return ""
	}
	return entry.name
}

func (c *dnsCache) reset() {
	c.mu.Lock()
	c.entries = make(map[netip.Addr]dnsCacheEntry)
	c.mu.Unlock()
}
