package coreapi

import "beam-bridge/core/paths"

// Options describes what a Core implementation needs to build a fresh instance.
// It mirrors the concrete engine's construction parameters without exposing the
// implementation type, so callers stay bound to coreapi alone.
type Options struct {
	Paths paths.Paths
}

// Factory builds a Core. It is the single seam through which bridge packages
// spin up a core without importing the concrete engine, keeping the engine
// reachable only via coreapi.
type Factory func(Options) Core
