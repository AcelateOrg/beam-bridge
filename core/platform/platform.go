package platform

import (
	"beam-bridge/core/types"
)

type Provider struct {
	LogCrashEvent           func(format string, args ...interface{})
	RecoverAndLog           func(context string)
	GetAppVersion           func() string
	GetOSVersion            func() string
	GetSystemLocale         func() string
	DeviceOSLabel           func() string
	IsDevBuild              func() bool
	ListRunningApplications func() ([]types.RunningApplication, error)
}

var (
	LogCrashEvent = func(format string, args ...interface{}) {}
	RecoverAndLog = func(context string) {}

	GetAppVersion   = func() string { return "" }
	GetOSVersion    = func() string { return "" }
	GetSystemLocale = func() string { return "" }
	DeviceOSLabel   = func() string { return "" }

	IsDevBuild = func() bool { return false }

	ListRunningApplications = func() ([]types.RunningApplication, error) {
		return nil, nil
	}
)

func Install(provider Provider) {
	if provider.LogCrashEvent != nil {
		LogCrashEvent = provider.LogCrashEvent
	}
	if provider.RecoverAndLog != nil {
		RecoverAndLog = provider.RecoverAndLog
	}
	if provider.GetAppVersion != nil {
		GetAppVersion = provider.GetAppVersion
	}
	if provider.GetOSVersion != nil {
		GetOSVersion = provider.GetOSVersion
	}
	if provider.GetSystemLocale != nil {
		GetSystemLocale = provider.GetSystemLocale
	}
	if provider.DeviceOSLabel != nil {
		DeviceOSLabel = provider.DeviceOSLabel
	}
	if provider.IsDevBuild != nil {
		IsDevBuild = provider.IsDevBuild
	}
	if provider.ListRunningApplications != nil {
		ListRunningApplications = provider.ListRunningApplications
	}
}
