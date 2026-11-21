package profile

import (
	"log"

	domainSettings "beam-bridge/core/domain/settings"
	infraBeam "beam-bridge/core/infrastructure/beam"
	"beam-bridge/core/types"
)

// withProviderCore подставляет фрагментацию, шум и Mux провайдера, если
// пользователь не включил свои: провайдер задаёт значения по умолчанию,
// но не выключает то, что пользователь включил сам.
func withProviderCore(core domainSettings.CoreSettings, ps *types.ProviderSettings) domainSettings.CoreSettings {
	if ps == nil {
		return core
	}
	if !core.Fragment.Enabled && (ps.Fragment != nil || len(ps.Noises) > 0) {
		f := domainSettings.FragmentSettings{Enabled: true, Preset: "custom", Direct: core.Fragment.Direct}
		if ps.Fragment != nil {
			f.Packets = ps.Fragment.Packets
			f.Length = ps.Fragment.Length
			f.Interval = ps.Fragment.Interval
			f.MaxSplit = ps.Fragment.MaxSplit
		}
		for _, n := range ps.Noises {
			f.Noises = append(f.Noises, domainSettings.NoiseSettings{Type: n.Type, Packet: n.Packet, Delay: n.Delay})
		}
		core.Fragment = f
	}
	if !core.Mux.Enabled && ps.Mux != nil {
		core.Mux = domainSettings.MuxSettings{
			Enabled:         true,
			Concurrency:     orInt(ps.Mux.Concurrency, 8),
			XUDPConcurrency: orInt(ps.Mux.XUDPConcurrency, 16),
			XUDPProxyUDP443: ps.Mux.XUDPProxyUDP443,
		}
		if core.Mux.XUDPProxyUDP443 == "" {
			core.Mux.XUDPProxyUDP443 = "reject"
		}
	}
	return core
}

func orInt(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}

// followProviderMove: new-url / new-domain — провайдер переехал, следующее
// обновление идёт с нового адреса.
func followProviderMove(beamFile *infraBeam.BeamFile) {
	ps := beamFile.Data.ProviderSettings
	if ps == nil || ps.NewURL == "" {
		return
	}
	log.Printf("profile: provider moved the subscription to a new URL")
	beamFile.Data.URL = ps.NewURL
	ps.NewURL = ""
}
