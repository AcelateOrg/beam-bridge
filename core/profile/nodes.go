package profile

import (
	"errors"
)

var (
	ErrProfileNotFound  = errors.New("profile not found")
	ErrNodeNotFound     = errors.New("node not found")
	ErrInvalidConfig    = errors.New("invalid configuration format")
	ErrSelectorNotFound = errors.New("selector not found in config")
)
