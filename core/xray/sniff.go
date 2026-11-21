package xray

import (
	"bytes"
	"net"
	"strings"
)

// sniffHost extracts the server name from the first bytes a client sends:
// the SNI of a TLS ClientHello or the Host header of an HTTP/1 request.
// Used for flows that bypass the core (the core sniffs its own). Returns ""
// when nothing is recognised.
func sniffHost(b []byte) string {
	if len(b) > 5 && b[0] == 0x16 && b[1] == 0x03 {
		return tlsServerName(b)
	}
	return httpHost(b)
}

// tlsServerName parses the server_name extension of a ClientHello. The
// hello may be cut short by the read; whatever is complete is used.
func tlsServerName(b []byte) string {
	// Record header (5) + handshake header (4).
	if len(b) < 9 || b[5] != 0x01 {
		return ""
	}
	p := b[9:]
	// client_version (2) + random (32).
	if len(p) < 34 {
		return ""
	}
	p = p[34:]

	skip := func(lenBytes int) bool {
		if len(p) < lenBytes {
			return false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(p[i])
		}
		if len(p) < lenBytes+n {
			return false
		}
		p = p[lenBytes+n:]
		return true
	}
	// session_id, cipher_suites, compression_methods.
	if !skip(1) || !skip(2) || !skip(1) {
		return ""
	}
	if len(p) < 2 {
		return ""
	}
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if extLen < len(p) {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		extType := int(p[0])<<8 | int(p[1])
		n := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if len(p) < n {
			return ""
		}
		data := p[:n]
		p = p[n:]
		if extType != 0 {
			continue
		}
		// server_name_list: length (2), then entries of type (1) + length (2).
		if len(data) < 2 {
			return ""
		}
		data = data[2:]
		for len(data) >= 3 {
			nameType := data[0]
			nameLen := int(data[1])<<8 | int(data[2])
			data = data[3:]
			if len(data) < nameLen {
				return ""
			}
			if nameType == 0 {
				return cleanHost(string(data[:nameLen]))
			}
			data = data[nameLen:]
		}
		return ""
	}
	return ""
}

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "),
	[]byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
}

func httpHost(b []byte) string {
	isHTTP := false
	for _, method := range httpMethods {
		if bytes.HasPrefix(b, method) {
			isHTTP = true
			break
		}
	}
	if !isHTTP {
		return ""
	}
	for _, line := range bytes.Split(b, []byte("\r\n")) {
		if len(line) == 0 {
			break
		}
		key, value, ok := bytes.Cut(line, []byte(":"))
		if ok && strings.EqualFold(string(bytes.TrimSpace(key)), "host") {
			host := strings.TrimSpace(string(value))
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			return cleanHost(host)
		}
	}
	return ""
}

// cleanHost keeps plausible host names only: IP literals are not names and
// garbage must not reach the UI.
func cleanHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || len(host) > 253 || net.ParseIP(host) != nil {
		return ""
	}
	for _, r := range host {
		if !(r == '-' || r == '.' || r == '_' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return ""
		}
	}
	return host
}
