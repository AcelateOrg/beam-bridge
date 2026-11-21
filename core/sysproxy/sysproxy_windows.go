//go:build windows

package sysproxy

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows: the per-connection options of WinINet for the LAN connection.
// Going through InternetSetOption (instead of writing the registry values
// by hand) also updates the binary DefaultConnectionSettings blob and makes
// running browsers pick the change up immediately.

const goos = "windows"

var (
	wininet                 = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOption   = wininet.NewProc("InternetSetOptionW")
	procInternetQueryOption = wininet.NewProc("InternetQueryOptionW")
)

const (
	internetOptionRefresh          = 37
	internetOptionSettingsChanged  = 39
	internetOptionPerConnection    = 75
	internetOptionProxySettingsChg = 95

	perConnFlags         = 1
	perConnProxyServer   = 2
	perConnProxyBypass   = 3
	perConnAutoConfigURL = 4

	proxyTypeDirect = 0x1
	proxyTypeProxy  = 0x2
)

// perConnOption mirrors INTERNET_PER_CONN_OPTIONW: a DWORD and a union of
// DWORD / LPWSTR / FILETIME (8 bytes).
type perConnOption struct {
	option uint32
	value  uint64
}

// perConnOptionList mirrors INTERNET_PER_CONN_OPTION_LISTW.
type perConnOptionList struct {
	size        uint32
	connection  *uint16
	optionCount uint32
	optionError uint32
	options     *perConnOption
}

type savedSettings struct {
	Flags         uint32 `json:"flags"`
	Server        string `json:"server"`
	Bypass        string `json:"bypass"`
	AutoConfigURL string `json:"autoConfigUrl"`
}

func supported() bool { return wininet.Load() == nil }

func prepareCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

func capture() (json.RawMessage, error) {
	options := []perConnOption{
		{option: perConnFlags},
		{option: perConnProxyServer},
		{option: perConnProxyBypass},
		{option: perConnAutoConfigURL},
	}
	list := perConnOptionList{
		optionCount: uint32(len(options)),
		options:     &options[0],
	}
	list.size = uint32(unsafe.Sizeof(list))
	size := list.size
	ret, _, callErr := procInternetQueryOption.Call(0, internetOptionPerConnection,
		uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Pointer(&size)))
	runtime.KeepAlive(options)
	if ret == 0 {
		return nil, fmt.Errorf("InternetQueryOption: %w", callErr)
	}

	saved := savedSettings{
		Flags:         uint32(options[0].value),
		Server:        takeString(&options[1].value),
		Bypass:        takeString(&options[2].value),
		AutoConfigURL: takeString(&options[3].value),
	}
	return json.Marshal(saved)
}

// takeString copies and frees a string returned by InternetQueryOption.
func takeString(field *uint64) string {
	p := *(**uint16)(unsafe.Pointer(field))
	if p == nil {
		return ""
	}
	s := windows.UTF16PtrToString(p)
	_, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(p))))
	return s
}

func apply(host string, port int) error {
	return setOptions(savedSettings{
		Flags:  proxyTypeDirect | proxyTypeProxy,
		Server: host + ":" + strconv.Itoa(port),
		Bypass: strings.Join(append(wildcardBypass(), "<local>"), ";"),
	})
}

func restore(raw json.RawMessage) error {
	var saved savedSettings
	if err := json.Unmarshal(raw, &saved); err != nil {
		return err
	}
	if saved.Flags == 0 {
		saved.Flags = proxyTypeDirect
	}
	return setOptions(saved)
}

func clearProxy() error {
	return setOptions(savedSettings{Flags: proxyTypeDirect})
}

func setOptions(s savedSettings) error {
	server, err := windows.UTF16PtrFromString(s.Server)
	if err != nil {
		return err
	}
	bypass, err := windows.UTF16PtrFromString(s.Bypass)
	if err != nil {
		return err
	}
	autoConfig, err := windows.UTF16PtrFromString(s.AutoConfigURL)
	if err != nil {
		return err
	}
	options := []perConnOption{
		{option: perConnFlags, value: uint64(s.Flags)},
		{option: perConnProxyServer, value: uint64(uintptr(unsafe.Pointer(server)))},
		{option: perConnProxyBypass, value: uint64(uintptr(unsafe.Pointer(bypass)))},
		{option: perConnAutoConfigURL, value: uint64(uintptr(unsafe.Pointer(autoConfig)))},
	}
	list := perConnOptionList{
		optionCount: uint32(len(options)),
		options:     &options[0],
	}
	list.size = uint32(unsafe.Sizeof(list))
	ret, _, callErr := procInternetSetOption.Call(0, internetOptionPerConnection,
		uintptr(unsafe.Pointer(&list)), uintptr(list.size))
	runtime.KeepAlive(server)
	runtime.KeepAlive(bypass)
	runtime.KeepAlive(autoConfig)
	runtime.KeepAlive(options)
	if ret == 0 {
		return fmt.Errorf("InternetSetOption: %w", callErr)
	}
	_, _, _ = procInternetSetOption.Call(0, internetOptionProxySettingsChg, 0, 0)
	_, _, _ = procInternetSetOption.Call(0, internetOptionSettingsChanged, 0, 0)
	_, _, _ = procInternetSetOption.Call(0, internetOptionRefresh, 0, 0)
	return nil
}
