package profile

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"beam-bridge/core/coreapi"
)

// userRule is one routing rule produced by the active routing mode, before
// it is written into the core config.
type userRule struct {
	object map[string]interface{}
	// apps referenced by the rule (matched through their inbound tags).
	apps []string
	// conditional: the rule also constrains domains or IPs.
	conditional bool
	outbound    string
	// networks limits the rule to "tcp" or "udp"; empty - both. The tunnel
	// knows the network of a flow, so this does not make a rule conditional.
	networks []string
	// label is the human-readable summary of the rule shown per
	// connection ("discord, youtube.com +2").
	label string
	// head is the ProTun card that feeds the destination.
	head string
}

// Rule tags let the core report which rule routed a flow. The tunnel and the
// UI read them as "<kind>|<n>|<label>".
const (
	ruleTagUser  = "user"
	ruleTagLAN   = "lan"
	ruleTagDNS   = "dns"
	ruleTagFinal = "final"
)

func ruleTag(kind string, n int, label string) string {
	label = strings.ReplaceAll(strings.TrimSpace(label), "|", "/")
	return kind + "|" + strconv.Itoa(n) + "|" + label
}

// labelOf summarises rule values: the first two, then "+N".
func labelOf(values []string) string {
	seen := make(map[string]bool, len(values))
	names := make([]string, 0, len(values))
	for _, value := range values {
		name := displayValue(value)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(names) <= 2 {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:2], ", ") + " +" + strconv.Itoa(len(names)-2)
}

// displayValue strips the core's matcher prefixes and app paths.
func displayValue(value string) string {
	value = strings.TrimSpace(value)
	if value == coreapi.OtherAppsKey {
		return "другие приложения"
	}
	for _, prefix := range []string{"full:", "domain:", "keyword:", "regexp:"} {
		value = strings.TrimPrefix(value, prefix)
	}
	if rest, ok := strings.CutPrefix(value, "geoip:"); ok {
		return strings.ToUpper(rest)
	}
	if rest, ok := strings.CutPrefix(value, "geosite:"); ok {
		return rest
	}
	// App paths (C:\...\discord.exe, /usr/bin/steam) show as the file name.
	if strings.Contains(value, `\`) || strings.HasPrefix(value, "/") {
		value = filepath.Base(strings.ReplaceAll(value, `\`, "/"))
	}
	if len(value) > 4 && strings.EqualFold(value[len(value)-4:], ".exe") {
		value = value[:len(value)-4]
	}
	return value
}

// planNetworks are the networks the tunnel decides separately.
var planNetworks = []string{"tcp", "udp"}

func (r userRule) covers(network string) bool {
	if len(r.networks) == 0 {
		return true
	}
	for _, n := range r.networks {
		if n == network {
			return true
		}
	}
	return false
}

func (r userRule) mentions(key string) bool {
	for _, app := range r.apps {
		if appKey(app) == key {
			return true
		}
	}
	return false
}

// appKey normalises an app the way the tunnel looks it up (lower-cased file
// name or full path, exactly as the user wrote it).
func appKey(app string) string {
	return strings.ToLower(strings.TrimSpace(app))
}

// appTag is the per-app inbound tag. One tag per app (not per app group)
// lets an app take part in any number of rules: each rule lists the tags of
// all its apps.
func appTag(app string) string {
	if appKey(app) == coreapi.OtherAppsKey {
		return coreapi.OtherAppsTag
	}
	return "beam-app-" + shortHash(appKey(app))
}

func appTags(apps []string) []string {
	seen := make(map[string]struct{}, len(apps))
	out := make([]string, 0, len(apps))
	for _, app := range apps {
		if appKey(app) == "" {
			continue
		}
		tag := appTag(app)
		if _, dup := seen[tag]; dup {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

// orderUserRules sorts rules by specificity, keeping the user's order inside
// each group: app+domain/IP rules first, then app-only rules, then
// domain/IP-only rules. An app rule is always more specific than a plain
// domain/IP rule, and the order makes the tunnel's per-app decision (bypass or
// block without entering the core) exactly equal to what the core routing
// would decide.
func orderUserRules(rules []userRule) []userRule {
	groups := [3][]userRule{}
	for _, rule := range rules {
		groups[ruleGroup(rule)] = append(groups[ruleGroup(rule)], rule)
	}
	out := make([]userRule, 0, len(rules))
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}

// ruleGroup: 0 - app + domain/IP, 1 - app only, 2 - domain/IP only.
func ruleGroup(rule userRule) int {
	switch {
	case len(rule.apps) > 0 && rule.conditional:
		return 0
	case len(rule.apps) > 0:
		return 1
	default:
		return 2
	}
}

// buildRoutePlan derives the tunnel-side plan from the ordered rules. An
// app's decision is taken from the first rule that mentions it: when that
// rule is unconditional, it decides every flow of the app.
//
// known lists every app named anywhere in the graphs. An app that is only
// excluded ("all apps except X") is in no rule, yet it must keep its own tag:
// otherwise the tunnel would treat it as "another app" and the exclusion
// would catch it.
func buildRoutePlan(ordered []userRule, finalOutbound string, known []string) coreapi.RoutePlan {
	plan := coreapi.RoutePlan{
		Apps:          make(map[string]coreapi.AppRoute),
		FinalOutbound: finalOutbound,
	}
	for _, rule := range ordered {
		for _, app := range rule.apps {
			key := appKey(app)
			if key == "" {
				continue
			}
			if _, decided := plan.Apps[key]; decided {
				continue
			}
			plan.Apps[key] = appRouteOf(ordered, key, appTag(app))
		}
	}
	if _, inverted := plan.Apps[coreapi.OtherAppsKey]; inverted {
		for _, app := range known {
			key := appKey(app)
			if key == "" {
				continue
			}
			if _, decided := plan.Apps[key]; !decided {
				plan.Apps[key] = appRouteOf(ordered, key, appTag(app))
			}
		}
	}

	byNetwork := make(map[string]bool, len(planNetworks))
	for _, network := range planNetworks {
		bypass := finalOutbound == outboundDirect
		for _, rule := range ordered {
			if len(rule.apps) == 0 && rule.outbound != outboundDirect && rule.covers(network) {
				bypass = false
				break
			}
		}
		byNetwork[network] = bypass
	}
	plan.DefaultBypass = byNetwork["tcp"] && byNetwork["udp"]
	if byNetwork["tcp"] != byNetwork["udp"] {
		plan.DefaultBypassNetworks = byNetwork
	}
	return plan
}

// appRouteOf takes, for each network, the first rule of the app that covers
// it. When both networks agree the route is a single verdict, as before
// network rules existed; otherwise it is split per network.
//
// With ProTun layers a plain (non-app) rule of the profile layer may come
// before the app's rule of the global layer. Such a rule is seen by the core
// first, so the tunnel must respect it: a conditional one makes the app's
// verdict conditional, an unconditional (network-only) one decides the
// network outright.
func appRouteOf(ordered []userRule, key, tag string) coreapi.AppRoute {
	verdicts := make(map[string]coreapi.NetRoute, len(planNetworks))
	for _, network := range planNetworks {
		shadowed := false
		var decider *userRule
		for i := range ordered {
			rule := ordered[i]
			if !rule.covers(network) {
				continue
			}
			if len(rule.apps) == 0 {
				if decider != nil {
					continue
				}
				if rule.conditional {
					shadowed = true
				} else {
					decider = &ordered[i]
				}
				continue
			}
			if !rule.mentions(key) {
				continue
			}
			source := rule
			if decider != nil {
				source = *decider
			}
			verdict := coreapi.NetRoute{}
			if !source.conditional && !shadowed {
				verdict.Outbound = source.outbound
				verdict.Bypass = source.outbound == outboundDirect
				verdict.Block = source.outbound == outboundBlock
			}
			verdicts[network] = verdict
			break
		}
	}

	route := coreapi.AppRoute{Tag: tag}
	tcp, hasTCP := verdicts["tcp"]
	udp, hasUDP := verdicts["udp"]
	if hasTCP && hasUDP && tcp == udp {
		route.Outbound, route.Bypass, route.Block = tcp.Outbound, tcp.Bypass, tcp.Block
		return route
	}
	route.Networks = verdicts
	return route
}

func ruleObjects(rules []userRule) []interface{} {
	out := make([]interface{}, 0, len(rules))
	for i, rule := range rules {
		rule.object["ruleTag"] = ruleTag(ruleTagUser, i+1, rule.label)
		out = append(out, rule.object)
	}
	return out
}
