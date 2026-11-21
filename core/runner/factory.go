package runner

import (
	"beam-bridge/core/coreapi"
	"beam-bridge/core/xray"
)

// CoreFactory builds a throwaway coreapi.Core backed by Xray. It lets bridge
// composition roots (which already depend on the engine) hand the concrete core
// to packages that must stay free of any xray import — e.g. profile ping — so
// the engine remains reachable only through coreapi.
var CoreFactory coreapi.Factory = xray.Factory
