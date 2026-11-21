package profile

import (
	"testing"

	domainSettings "beam-bridge/core/domain/settings"
	"beam-bridge/core/types"
)

func TestWithProviderCore(t *testing.T) {
	ps := &types.ProviderSettings{
		Noises: []types.ProviderNoise{{Type: "rand", Packet: "10-20", Delay: "10-16"}},
		Mux:    &types.ProviderMux{Concurrency: 4},
	}
	core := withProviderCore(domainSettings.CoreSettings{}, ps)
	if !core.Fragment.Enabled || len(core.Fragment.Noises) != 1 {
		t.Fatalf("fragment = %+v", core.Fragment)
	}
	settings := fragmentSettings(core.Fragment)
	if _, has := settings["fragment"]; has {
		t.Errorf("noise-only provider must not fragment: %v", settings)
	}
	if !core.Mux.Enabled || core.Mux.Concurrency != 4 || core.Mux.XUDPConcurrency != 16 || core.Mux.XUDPProxyUDP443 != "reject" {
		t.Errorf("mux = %+v", core.Mux)
	}

	own := domainSettings.CoreSettings{Fragment: domainSettings.FragmentSettings{Enabled: true, Preset: "strong"}}
	if got := withProviderCore(own, ps); got.Fragment.Preset != "strong" || len(got.Fragment.Noises) != 0 {
		t.Errorf("user fragmentation must win: %+v", got.Fragment)
	}
}
