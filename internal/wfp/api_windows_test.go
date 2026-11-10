package wfp

import (
	"os"
	"testing"
)

// Opt-in read-only integration check: opens/closes sessions, never starts a transaction.
func TestOpenReturnsNonzeroHandle(t *testing.T) {
	if os.Getenv("KS_TEST_WFP_READ_ONLY") != "1" {
		t.Skip("set KS_TEST_WFP_READ_ONLY=1 to open read-only WFP sessions")
	}
	for i := 0; i < 20; i++ {
		done := make(chan struct{})
		go func() {
			defer close(done)
			e, err := Open()
			if err != nil {
				t.Errorf("Open: %v", err)
				return
			}
			if e.handle == 0 {
				t.Error("Open succeeded with a null engine handle")
			}
			if err := e.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
		<-done
	}
}

func TestFilterApplication(t *testing.T) {
	for _, tc := range []struct {
		name, displayName, want string
		action                  uint32
		ok                      bool
	}{
		{name: "block", displayName: `KS guard v1 BLOCK C:\Apps\app.exe`, action: actionBlock, want: `C:\Apps\app.exe`, ok: true},
		{name: "permit", displayName: `KS guard v1 PERMIT_SOFT D:\Apps\other.exe`, action: actionPermit, want: `D:\Apps\other.exe`, ok: true},
		{name: "wrong action", displayName: `KS guard v1 BLOCK C:\Apps\app.exe`, action: actionPermit},
		{name: "missing application", displayName: `KS guard v1 BLOCK `, action: actionBlock},
		{name: "foreign name", displayName: `Other filter`, action: actionBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := filterApplication(tc.displayName, tc.action)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("application=%q ok=%v, want %q %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}
