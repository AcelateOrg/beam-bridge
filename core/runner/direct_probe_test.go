package runner

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// Android establishes the VPN before the core stack is ready. A probe must
// still run the protector and must not silently fall back if it rejects a socket.
func TestDialDirectProtectsBeforeStackStarts(t *testing.T) {
	svc := &Service{}
	rejected := errors.New("socket protection rejected")
	calls := 0
	svc.SetDeviceDialControl(func(_, _ string, _ syscall.RawConn) error {
		calls++
		return rejected
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := svc.DialDirect(ctx, "tcp", "127.0.0.1:9")
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, rejected) || calls != 1 {
		t.Fatalf("unprotected probe: calls=%d err=%v", calls, err)
	}
}

func TestDialDirectWithoutPlatformHook(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	svc := &Service{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := svc.DialDirect(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}
