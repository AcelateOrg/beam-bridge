//go:build !windows && !darwin && (!linux || android)

package sysproxy

import (
	"encoding/json"
	"errors"
	"os/exec"
)

const goos = "other"

var errUnsupported = errors.New("system proxy is not supported on this platform")

func supported() bool                   { return false }
func prepareCommand(*exec.Cmd)          {}
func capture() (json.RawMessage, error) { return nil, errUnsupported }
func apply(string, int) error           { return errUnsupported }
func restore(json.RawMessage) error     { return errUnsupported }
func clearProxy() error                 { return errUnsupported }
