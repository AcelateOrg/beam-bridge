package xray

import (
	"syscall"

	"github.com/xtls/xray-core/transport/internet"
)

// RegisterSocketControl runs control on every socket the engine dials or
// listens on, before it connects. Platforms whose tunnel would otherwise
// capture the engine's own traffic (Android's VpnService.protect) hook in
// here. Controls are process-wide and cannot be removed, so register once.
func RegisterSocketControl(control func(network, address string, c syscall.RawConn) error) error {
	if err := internet.RegisterDialerController(control); err != nil {
		return err
	}
	return internet.RegisterListenerController(control)
}
