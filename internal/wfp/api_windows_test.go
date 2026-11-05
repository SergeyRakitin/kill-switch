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
