// beamlink encodes a profile JSON into a beam:// link and back, the same way
// Beam reads them (docs/beam-links.md). It is the reference for generators.
//
//	go run ./cmd/beamlink encode profile.json      -> beam://import/...
//	go run ./cmd/beamlink decode 'beam://import/...' -> JSON
//	go run ./cmd/beamlink check  profile.json      -> what Beam would import
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"beam-bridge/core/infrastructure/beam"
	"beam-bridge/core/infrastructure/subscription"
)

const prefix = "beam://import/"

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: beamlink encode|decode|check <file|link>")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "encode":
		err = encode(os.Args[2])
	case "decode":
		err = decode(os.Args[2])
	case "check":
		err = check(os.Args[2])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func encode(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Compact first: whitespace costs link length.
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return err
	}
	var zipped bytes.Buffer
	w, _ := gzip.NewWriterLevel(&zipped, gzip.BestCompression)
	if _, err := w.Write(compact.Bytes()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	link := prefix + base64.RawURLEncoding.EncodeToString(zipped.Bytes())
	fmt.Println(link)
	fmt.Fprintf(os.Stderr, "json %d B -> link %d chars\n", compact.Len(), len(link))
	return nil
}

func decode(link string) error {
	payload := strings.TrimPrefix(strings.TrimSpace(link), prefix)
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(payload, "="))
	if err != nil {
		return fmt.Errorf("not base64url: %w", err)
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("not gzip: %w", err)
	}
	content, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("broken gzip (truncated link?): %w", err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, content, "", "  "); err != nil {
		return err
	}
	fmt.Println(pretty.String())
	return nil
}

func check(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	bf, err := beam.ParseData(raw)
	if err != nil {
		return err
	}
	if err := subscription.NewAggregator(nil).ExpandLinks(bf); err != nil {
		return err
	}
	fmt.Printf("name: %s, provider: %s, url: %s\n", bf.Data.Name, bf.Data.Provider, bf.Data.URL)
	if b := bf.Data.EffectiveBranding(); b != nil {
		before := *b
		b.Sanitize()
		if *b != before {
			fmt.Println("warning: some branding values are not allowed and will be dropped")
		}
	}
	groups := map[string]string{}
	for _, c := range bf.Data.Categories {
		name := c.Name
		if c.Emoji != "" {
			name = c.Emoji + " " + name
		}
		if c.Collapsed {
			name += ", collapsed"
		}
		groups[c.ID] = name
	}
	for _, n := range bf.Data.Nodes {
		line := fmt.Sprintf("  [%s] %s (%s)", groups[n.CategoryID], n.Name, n.Type)
		if n.Description != "" {
			line += " — " + n.Description
		}
		if n.Badge != "" {
			line += " {" + n.Badge + "}"
		}
		fmt.Println(line)
	}
	if len(bf.Data.Nodes) == 0 {
		return fmt.Errorf("no servers: Beam would reject this profile")
	}
	return nil
}
