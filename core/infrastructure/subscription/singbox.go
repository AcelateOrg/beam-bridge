package subscription

import (
	"log"

	"beam-bridge/core/infrastructure/subscription/parsers"
)

// SingBoxProxies returns the proxy outbounds of a sing-box config with each
// "detour" tag replaced by the outbound it names, so a chain survives as a
// nested map in the node (the internal format keeps "detour" as an object).
func SingBoxProxies(outbounds []interface{}) []map[string]interface{} {
	byTag := make(map[string]map[string]interface{}, len(outbounds))
	for _, item := range outbounds {
		if ob, ok := item.(map[string]interface{}); ok {
			if tag := str(ob, "tag"); tag != "" {
				byTag[tag] = ob
			}
		}
	}
	var proxies []map[string]interface{}
	for _, item := range outbounds {
		ob, ok := item.(map[string]interface{})
		if !ok || parsers.IsServiceOutbound(str(ob, "type")) || str(ob, "tag") == "" {
			continue
		}
		proxies = append(proxies, resolveDetour(ob, byTag, map[string]bool{}, 0))
	}
	return proxies
}

func resolveDetour(ob map[string]interface{}, byTag map[string]map[string]interface{}, visiting map[string]bool, depth int) map[string]interface{} {
	out := make(map[string]interface{}, len(ob))
	for k, v := range ob {
		out[k] = v
	}
	tag, isTag := ob["detour"].(string)
	if !isTag {
		return out
	}
	delete(out, "detour")
	visiting[str(ob, "tag")] = true
	target := byTag[tag]
	switch {
	case target == nil:
		log.Printf("subscription: detour %q of %q not found, dropped", tag, str(ob, "tag"))
	case depth >= maxDetourDepth || visiting[tag]:
		log.Printf("subscription: detour chain at %q is too deep or cyclic, dropped", tag)
	case str(target, "type") == "direct" && len(target) <= 2:
		// A bare direct hop is what the outbound does anyway.
	case parsers.IsServiceOutbound(str(target, "type")) && str(target, "type") != "direct":
		log.Printf("subscription: detour %q is a %s outbound, dropped", tag, str(target, "type"))
	default:
		out["detour"] = resolveDetour(target, byTag, visiting, depth+1)
	}
	return out
}
