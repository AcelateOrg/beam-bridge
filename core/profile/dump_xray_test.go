package profile

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"

	domainSettings "beam-bridge/core/domain/settings"
	infraBeam "beam-bridge/core/infrastructure/beam"
	"beam-bridge/core/types"
)

// TestDumpXrayConfig prints the config the Xray core actually receives for a
// given profile. Run with BEAM_DUMP_PROFILE pointing at a .beam file.
func TestDumpXrayConfig(t *testing.T) {
	path := os.Getenv("BEAM_DUMP_PROFILE")
	if path == "" {
		t.Skip("BEAM_DUMP_PROFILE не задан")
	}

	bf, err := infraBeam.ReadFromFile(path)
	if err != nil {
		t.Fatalf("профиль не прочитан: %v", err)
	}

	builder := NewXrayConfigBuilder(
		domainSettings.ConnectionSettings{Mode: "tun", PrimaryDNS: "8.8.8.8"},
		types.SplitTunnelSettings{},
	)
	generated := builder.BuildFromBeam(bf)
	if generated == nil {
		t.Fatal("конфиг не собрался (nil)")
	}
	t.Logf("selected=%s unsupported=%v", generated.ProxyTag, generated.UnsupportedNodes)

	raw, err := json.MarshalIndent(generated.Config, "", "  ")
	if err != nil {
		t.Fatalf("не сериализуется: %v", err)
	}
	masked := regexp.MustCompile(`"id":\s*"[^"]*"`).ReplaceAllString(string(raw), `"id": "***"`)
	t.Logf("---- xray config ----\n%s", masked)
}
