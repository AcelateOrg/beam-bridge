package xray

import "beam-bridge/core/coreapi"

// Instance is the Xray-backed implementation of coreapi.Core.
var _ coreapi.Core = (*Instance)(nil)

// Factory adapts the Xray instance constructor to coreapi.Factory so other
// bridge packages can build a core through the coreapi seam alone, without
// importing this package directly.
func Factory(opts coreapi.Options) coreapi.Core {
	return New(Options{Paths: opts.Paths})
}
