package subscription

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"beam-bridge/core/types"
)

// A panel cannot serve a .beam file, so the ProTun preset rides in a
// response header (or a "#beam-protun: ..." body line). Header values are
// single-line ASCII and proxies cap them at a few KB, which a pretty-printed
// .protun with Cyrillic labels never survives; hence base64, optionally over
// gzip. Remnawave: Response Rule for user-agent "BEAM/".
const (
	ProTunHeader       = "Beam-Protun"        // base64(.protun JSON) or base64(gzip(.protun JSON))
	ProTunLockedHeader = "Beam-Protun-Locked" // true: the preset is forced and read-only
)

const (
	maxProTunHeader  = 256 << 10
	maxProTunJSON    = 1 << 20
	maxProTunNodes   = 500
	maxProTunEdges   = 2000
	proTunFileFormat = "protun"
)

// applyProTunHeader installs the provider's routing preset. A preset the
// document already carries (hosted .beam) wins.
func applyProTunHeader(d *types.BeamFileData, header http.Header, meta *SubscriptionMeta) {
	if d.ProTunPreset != nil {
		return
	}
	graph := decodeProTunPreset(proTunValue(header, meta, ProTunHeader))
	if graph == nil {
		return
	}
	d.ProTunPreset = graph
	d.ProTunLocked = parseBoolMeta(proTunValue(header, meta, ProTunLockedHeader))
}

func proTunValue(header http.Header, meta *SubscriptionMeta, key string) string {
	if header != nil {
		// A proxy that folds a long header into several lines hands them
		// over as separate values of the same key.
		if v := strings.TrimSpace(strings.Join(header.Values(key), "")); v != "" {
			return v
		}
	}
	if meta != nil {
		return strings.TrimSpace(meta.Raw[strings.ToLower(key)])
	}
	return ""
}

func decodeProTunPreset(raw string) *types.ProTunGraph {
	if raw == "" || len(raw) > maxProTunHeader {
		return nil
	}
	data := []byte(raw)
	if !strings.HasPrefix(raw, "{") {
		// Panels and proxies wrap or pad long values.
		compact := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, strings.TrimPrefix(raw, "base64:"))
		decoded, err := decodeBase64(compact)
		if err != nil {
			return nil
		}
		data = decoded
	}
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil
		}
		defer reader.Close()
		inflated, err := io.ReadAll(io.LimitReader(reader, maxProTunJSON+1))
		if err != nil {
			return nil
		}
		data = inflated
	}
	if len(data) > maxProTunJSON {
		return nil
	}

	// Either a whole .protun export or the bare graph.
	var doc struct {
		Format string             `json:"format"`
		Graph  *types.ProTunGraph `json:"graph"`
		types.ProTunGraph
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	graph := doc.Graph
	if graph == nil {
		if doc.Format != "" && doc.Format != proTunFileFormat {
			return nil
		}
		graph = &doc.ProTunGraph
	}
	if len(graph.Nodes) == 0 || len(graph.Nodes) > maxProTunNodes || len(graph.Edges) > maxProTunEdges {
		return nil
	}
	if graph.Edges == nil {
		graph.Edges = []types.ProTunEdge{}
	}
	// The provider's canvas position means nothing on the user's screen.
	graph.Viewport = nil
	return graph
}
