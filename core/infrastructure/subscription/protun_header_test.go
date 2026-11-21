package subscription

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"net/http"
	"testing"

	"beam-bridge/core/types"
)

const proTunExport = `{
  "format": "protun",
  "version": 1,
  "meta": { "name": "Россия напрямую" },
  "graph": {
    "nodes": [
      { "id": "a", "kind": "geosite", "position": { "x": 0, "y": 0 }, "label": "РФ-сайты", "items": ["category-ru"] },
      { "id": "b", "kind": "direct", "position": { "x": 300, "y": 0 } }
    ],
    "edges": [{ "id": "e", "source": "a", "target": "b" }],
    "viewport": { "x": 1, "y": 2, "zoom": 0.5 }
  }
}`

func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestProTunHeaderEncodings(t *testing.T) {
	std := base64.StdEncoding.EncodeToString([]byte(proTunExport))
	cases := map[string]string{
		"base64":          std,
		"base64 prefix":   "base64:" + std,
		"base64url nopad": base64.RawURLEncoding.EncodeToString([]byte(proTunExport)),
		"gzip":            base64.StdEncoding.EncodeToString(gzipped(t, proTunExport)),
		"wrapped":         std[:40] + " \r\n " + std[40:],
		"bare graph":      base64.StdEncoding.EncodeToString([]byte(`{"nodes":[{"id":"a","kind":"vpn","position":{"x":0,"y":0}},{"id":"b","kind":"domains","position":{"x":0,"y":0},"label":"Сайты"}],"edges":[{"id":"e","source":"b","target":"a"}]}`)),
	}
	for name, value := range cases {
		h := http.Header{}
		h.Set(ProTunHeader, value)
		var d types.BeamFileData
		applyProTunHeader(&d, h, nil)
		if d.ProTunPreset == nil || len(d.ProTunPreset.Nodes) != 2 || len(d.ProTunPreset.Edges) != 1 {
			t.Errorf("%s: preset = %+v", name, d.ProTunPreset)
			continue
		}
		if d.ProTunPreset.Viewport != nil || d.ProTunLocked {
			t.Errorf("%s: viewport=%v locked=%v", name, d.ProTunPreset.Viewport, d.ProTunLocked)
		}
	}
}

func TestProTunHeaderKeepsUnicode(t *testing.T) {
	h := http.Header{}
	h.Set(ProTunHeader, base64.StdEncoding.EncodeToString(gzipped(t, proTunExport)))
	h.Set(ProTunLockedHeader, "true")
	var d types.BeamFileData
	applyProTunHeader(&d, h, nil)
	if d.ProTunPreset == nil || d.ProTunPreset.Nodes[0].Label != "РФ-сайты" || !d.ProTunLocked {
		t.Fatalf("preset = %+v locked = %v", d.ProTunPreset, d.ProTunLocked)
	}
}

func TestProTunFromBodyMeta(t *testing.T) {
	meta := ParseSubscriptionMeta([]string{
		"#beam-protun: " + base64.StdEncoding.EncodeToString([]byte(proTunExport)),
		"#beam-protun-locked: 1",
	})
	var d types.BeamFileData
	applyProTunHeader(&d, http.Header{}, meta)
	if d.ProTunPreset == nil || !d.ProTunLocked {
		t.Fatalf("preset = %+v locked = %v", d.ProTunPreset, d.ProTunLocked)
	}
}

func TestProTunHeaderRejects(t *testing.T) {
	bad := []string{
		"",
		"not base64 !!!",
		base64.StdEncoding.EncodeToString([]byte(`{"nodes":[],"edges":[]}`)),
		base64.StdEncoding.EncodeToString([]byte(`{"format":"beam","nodes":[{"id":"a","kind":"vpn"}]}`)),
		base64.StdEncoding.EncodeToString([]byte(`[1,2,3]`)),
	}
	for _, value := range bad {
		h := http.Header{}
		h.Set(ProTunHeader, value)
		var d types.BeamFileData
		applyProTunHeader(&d, h, nil)
		if d.ProTunPreset != nil {
			t.Errorf("%q: want no preset, got %+v", value, d.ProTunPreset)
		}
	}
}

func TestProTunHeaderDoesNotOverrideFile(t *testing.T) {
	own := &types.ProTunGraph{Nodes: []types.ProTunNode{{ID: "own"}}}
	d := types.BeamFileData{ProTunPreset: own}
	h := http.Header{}
	h.Set(ProTunHeader, base64.StdEncoding.EncodeToString([]byte(proTunExport)))
	h.Set(ProTunLockedHeader, "true")
	applyProTunHeader(&d, h, nil)
	if d.ProTunPreset != own || d.ProTunLocked {
		t.Fatalf("file preset was replaced: %+v locked=%v", d.ProTunPreset, d.ProTunLocked)
	}
}
