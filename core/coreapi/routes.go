package coreapi

// OtherAppsKey is the RoutePlan.Apps entry for apps the plan does not list
// by name ("all apps except ..." cards). Flows whose owner is unknown do
// not use it: an excluded app must never be mistaken for "another" one.
const OtherAppsKey = "*"

// OtherAppsTag is the inbound tag of OtherAppsKey flows.
const OtherAppsTag = "beam-app-other"

// NetRoute is the verdict of an app's rules for one network ("tcp"/"udp")
// when the app's rules differ between networks.
type NetRoute struct {
	// Outbound of the unconditional rule; empty when the first rule for
	// this network is conditional and only the core can evaluate it.
	Outbound string
	Bypass   bool
	Block    bool
}

// AppRoute is the tunnel-side routing decision for one app, compiled from
// the active routing mode (easy split tunnel or ProTun graph).
type AppRoute struct {
	// Tag is the inbound tag the core routing rules match this app by.
	Tag string
	// Outbound is the outbound of the app's unconditional rule; empty when
	// the app only appears in conditional rules (app + domain/IP), which
	// only the core can evaluate.
	Outbound string
	// Bypass: every flow of the app goes direct, so the tunnel dials it
	// through the physical interface without entering the core at all.
	Bypass bool
	// Block: every flow of the app is blocked.
	Block bool
	// Networks, when set, replaces Outbound/Bypass/Block per network: the
	// app's rules send TCP and UDP to different places. A network missing
	// from the map has no rule of the app and follows the defaults.
	Networks map[string]NetRoute
}

// RoutePlan is the complete routing contract between the profile builder and
// the tunnel. Apps are keyed by the lower-cased app as the user wrote it
// (file name or full path).
type RoutePlan struct {
	Apps map[string]AppRoute
	// FinalOutbound receives everything no rule matched.
	FinalOutbound string
	// DefaultBypass: flows of apps without a route go direct as a whole
	// (final outbound is direct and no domain/IP rule can send them
	// elsewhere), so the tunnel may bypass the core for them too.
	DefaultBypass bool
	// DefaultBypassNetworks, when set, replaces DefaultBypass per network.
	DefaultBypassNetworks map[string]bool
	// DisableBypass: direct traffic must pass the core (its direct outbound
	// fragments it), so the tunnel never skips the core.
	DisableBypass bool
}
