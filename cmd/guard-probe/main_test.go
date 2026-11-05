package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPSMonitorSurvivesFailuresAndRecovers(t *testing.T) {
	var calls atomic.Int32
	request := func(context.Context) httpsResult {
		switch calls.Add(1) {
		case 1, 4:
			return httpsResult{status: 204}
		default:
			return httpsResult{err: context.DeadlineExceeded}
		}
	}
	err := monitorHTTPS(context.Background(), "https://example.invalid/test", 4, 0, time.Second, nil, request)
	if err != nil || calls.Load() != 4 {
		t.Fatalf("attempts=%d err=%v", calls.Load(), err)
	}
}

func TestHTTPSMonitorStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	err := monitorHTTPS(ctx, "https://example.invalid/test", 0, 0, time.Second, nil, func(context.Context) httpsResult { calls.Add(1); cancel(); return httpsResult{status: 200} })
	if err != nil || calls.Load() != 1 {
		t.Fatalf("attempts=%d err=%v", calls.Load(), err)
	}
}

func TestHTTPSLocalServerAndTLS(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/elsewhere", 302)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer s.Close()
	c := s.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r := httpsOnce(context.Background(), c, s.URL+"/test")
	if r.err != nil || r.status != 200 || r.bytes != 2 {
		t.Fatalf("response: %+v", r)
	}
	r = httpsOnce(context.Background(), c, s.URL+"/redirect")
	if r.err != nil || r.status != 302 {
		t.Fatalf("redirect: %+v", r)
	}
	untrusted := newHTTPSClient(time.Second)
	defer untrusted.CloseIdleConnections()
	r = httpsOnce(context.Background(), untrusted, s.URL)
	if r.err == nil {
		t.Fatal("untrusted TLS accepted")
	}
}

func TestMarkerValidation(t *testing.T) {
	good := "kill-switch-probe 1234567890abcdef 2 2026-11-04T12:00:00Z\n"
	if !validMarker(good) || validMarker("wrong\n") || validMarker(good+"extra") {
		t.Fatal("marker validation")
	}
}

func TestTCPPartialAndInvalidACK(t *testing.T) {
	for _, valid := range []bool{true, false} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			c, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			defer c.Close()
			line, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			ack := "ack " + line
			if !valid {
				ack = "ack wrong\n"
			}
			_, err = c.Write([]byte(ack[:3]))
			if err == nil {
				time.Sleep(5 * time.Millisecond)
				_, err = c.Write([]byte(ack[3:]))
			}
			done <- err
		}()
		marker := "kill-switch-probe 1234567890abcdef 0 2026-11-04T12:00:00Z\n"
		err = tcp(listener.Addr().String(), marker, time.Second)
		listener.Close()
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		if valid && err != nil {
			t.Fatal(err)
		}
		if !valid && err == nil {
			t.Fatal("bad ACK accepted")
		}
	}
}

func TestUDPACKValidation(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	marker := "kill-switch-probe 1234567890abcdef 0 2026-11-04T12:00:00Z\n"
	for _, valid := range []bool{true, false} {
		done := make(chan error, 1)
		go func() {
			buf := make([]byte, 256)
			n, from, err := server.ReadFromUDP(buf)
			if err != nil {
				done <- err
				return
			}
			ack := "ack " + string(buf[:n])
			if !valid {
				ack = "ack wrong\n"
			}
			_, err = server.WriteToUDP([]byte(ack), from)
			done <- err
		}()
		err = udp(server.LocalAddr().String(), marker, time.Second, false)
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		if valid && err != nil {
			t.Fatal(err)
		}
		if !valid && err == nil {
			t.Fatal("bad UDP ACK accepted")
		}
	}
}
