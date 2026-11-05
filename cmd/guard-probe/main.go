// guard-probe sends explicit test markers only to a user supplied receiver.
// It never changes WFP, VPN, routes, DNS, or proxy settings.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"kill-switch/internal/runlog"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "guard-probe:", err)
		os.Exit(1)
	}
}

func run(args []string) (result error) {
	fs := flag.NewFlagSet("guard-probe", flag.ContinueOnError)
	mode := fs.String("mode", "", "https-monitor | tcp | tcp-hold | udp | udp-hold | udp-sendto | dns | tcp-listen | udp-listen | child")
	target := fs.String("target", "", "receiver host:port or test hostname for dns")
	childPath := fs.String("child-path", "", "distinct probe executable path for child test")
	childMode := fs.String("child-mode", "tcp", "network mode for child")
	parentRunID := fs.String("parent-run-id", "", "parent probe run ID")
	count := fs.Int("count", 1, "markers to send; max 1000")
	interval := fs.Duration("interval", time.Second, "spacing for repeated markers")
	timeout := fs.Duration("timeout", 5*time.Second, "deadline for each operation")
	logDir := fs.String("log-dir", "", "JSONL log directory")
	logLevel := fs.String("log-level", "info", "info or debug")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected argument")
	}
	if *target == "" || *count < 0 || *count > 1000 || (*count == 0 && *mode != "https-monitor") || *interval < 0 || *timeout <= 0 {
		return errors.New("explicit target, count 1..1000 (or 0 for continuous HTTPS) and positive timeout required")
	}
	if *mode != "https-monitor" && *mode != "tcp" && *mode != "tcp-hold" && *mode != "udp" && *mode != "udp-hold" && *mode != "udp-sendto" && *mode != "dns" && *mode != "tcp-listen" && *mode != "udp-listen" && *mode != "child" {
		return errors.New("unknown probe mode")
	}
	if *mode != "dns" && *mode != "https-monitor" {
		if _, _, err := net.SplitHostPort(*target); err != nil {
			return err
		}
	}
	if *mode == "https-monitor" {
		if err := validateHTTPSURL(*target); err != nil {
			return err
		}
	}
	token := make([]byte, 8)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	id := hex.EncodeToString(token)
	journal, logErr := runlog.New("guard-probe", *logDir, *logLevel, "", id)
	if logErr != nil {
		fmt.Fprintln(os.Stderr, "guard-probe log:", logErr)
	}
	started := time.Now()
	defer func() {
		outcome := "completed"
		if result != nil {
			outcome = "error"
		}
		journal.Close(outcome, time.Since(started))
	}()
	journal.Event("probe_start", "started", 0, "mode", *mode, "target", *target, "count", *count, "interval", interval.String(), "timeout", timeout.String())
	if *parentRunID != "" {
		journal.Event("child_start", "started", 0, "parentRunId", *parentRunID)
	}
	fmt.Printf("probe id=%s mode=%s target=%s count=%d\n", id, *mode, *target, *count)
	if *mode == "https-monitor" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return monitorHTTPS(ctx, *target, *count, *interval, *timeout, journal, nil)
	}
	if *mode == "tcp-listen" {
		return listenTCP(*target, *count, *timeout, journal)
	}
	if *mode == "udp-listen" {
		return listenUDP(*target, *count, *timeout, journal)
	}
	if *mode == "child" {
		if *childPath == "" || *childMode == "child" || *childMode == "tcp-listen" || *childMode == "udp-listen" {
			return errors.New("--child-path and a client --child-mode required")
		}
		cmd := exec.Command(*childPath, "--mode", *childMode, "--target", *target, "--count", fmt.Sprint(*count), "--interval", interval.String(), "--timeout", timeout.String(), "--parent-run-id", id, "--log-level", *logLevel)
		if *logDir != "" {
			cmd.Args = append(cmd.Args, "--log-dir", *logDir)
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		start := time.Now()
		journal.Event("child_spawn", "started", 0, "parentRunId", id, "childPath", *childPath, "childMode", *childMode)
		err := cmd.Run()
		outcome := "ok"
		if err != nil {
			outcome = "error"
		}
		journal.Event("child_end", outcome, time.Since(start), "parentRunId", id, "childPid", func() int {
			if cmd.Process != nil {
				return cmd.Process.Pid
			}
			return 0
		}(), "childPath", *childPath, "exitCode", childExitCode(err), "error", fmt.Sprint(err))
		return err
	}
	if *mode == "tcp-hold" || *mode == "udp-hold" {
		return hold(*mode, *target, *count, *interval, *timeout, id, journal)
	}
	attempted, succeeded := 0, 0
	defer func() {
		journal.Event("probe_summary", "observed", 0, "requested", *count, "attempted", attempted, "successes", succeeded, "failures", attempted-succeeded, "complete", attempted == *count)
	}()
	for i := 0; i < *count; i++ {
		if i > 0 {
			time.Sleep(*interval)
		}
		marker := fmt.Sprintf("kill-switch-probe %s %d %s\n", id, i, time.Now().UTC().Format(time.RFC3339Nano))
		attemptStarted := time.Now()
		attempted++
		var err error
		switch *mode {
		case "tcp":
			err = tcp(*target, marker, *timeout)
		case "udp":
			err = udp(*target, marker, *timeout, true)
		case "udp-sendto":
			err = udp(*target, marker, *timeout, false)
		case "dns":
			err = dns(*target, *timeout)
		}
		fmt.Printf("%s seq=%d error=%v\n", time.Now().UTC().Format(time.RFC3339Nano), i, err)
		outcome := "success"
		if err != nil {
			outcome = "error"
		}
		if err == nil {
			succeeded++
		}
		var detail any
		if err != nil {
			detail = map[string]any{"kind": errorKind(err), "message": err.Error()}
		}
		journal.Event("probe_attempt", outcome, time.Since(attemptStarted), "seq", i, "error", detail)
		if err != nil {
			return err
		}
	}
	return nil
}

func childExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

type httpsResult struct {
	status                               int
	bytes                                int
	err                                  error
	local, remote, family                string
	dnsMs, connectMs, tlsMs, firstByteMs int64
}

func newHTTPSClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: false}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func httpsOnce(ctx context.Context, client *http.Client, target string) httpsResult {
	r := httpsResult{}
	var dnsStart, connectStart, tlsStart, requestStart time.Time
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsStart = time.Now() }, DNSDone: func(httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				r.dnsMs = time.Since(dnsStart).Milliseconds()
			}
		},
		ConnectStart: func(_, _ string) { connectStart = time.Now() }, ConnectDone: func(_, _ string, _ error) {
			if !connectStart.IsZero() {
				r.connectMs = time.Since(connectStart).Milliseconds()
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() }, TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			if !tlsStart.IsZero() {
				r.tlsMs = time.Since(tlsStart).Milliseconds()
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			r.local = info.Conn.LocalAddr().String()
			r.remote = info.Conn.RemoteAddr().String()
			if host, _, err := net.SplitHostPort(r.remote); err == nil {
				if ip := net.ParseIP(host); ip != nil {
					if ip.To4() != nil {
						r.family = "IPv4"
					} else {
						r.family = "IPv6"
					}
				}
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { requestStart = time.Now() }, GotFirstResponseByte: func() {
			if !requestStart.IsZero() {
				r.firstByteMs = time.Since(requestStart).Milliseconds()
			}
		},
	}
	ctx = httptrace.WithClientTrace(ctx, trace)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		r.err = err
		return r
	}
	req.Header.Set("User-Agent", "guard-probe/1")
	resp, err := client.Do(req)
	if err != nil {
		r.err = err
		return r
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	r.status = resp.StatusCode
	r.bytes = int(n)
	r.err = err
	return r
}

func validateHTTPSURL(target string) error {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return errors.New("specify an explicit HTTPS URL without credentials, query or fragment")
	}
	if strings.Contains(target, "\n") {
		return errors.New("invalid URL")
	}
	return nil
}

func errorKind(err error) string {
	if err == nil {
		return ""
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return "tls"
	}
	var host x509.HostnameError
	if errors.As(err, &host) {
		return "tls"
	}
	var record tls.RecordHeaderError
	if errors.As(err, &record) {
		return "tls"
	}
	return "network"
}

func monitorHTTPS(ctx context.Context, target string, count int, interval, timeout time.Duration, journal *runlog.Log, request func(context.Context) httpsResult) error {
	if err := validateHTTPSURL(target); err != nil {
		return err
	}
	if request == nil {
		client := newHTTPSClient(timeout)
		defer client.CloseIdleConnections()
		request = func(ctx context.Context) httpsResult { return httpsOnce(ctx, client, target) }
	}
	successes, failures := 0, 0
	lastResponded := false
	everResponded := false
	for seq := 0; count == 0 || seq < count; seq++ {
		if ctx.Err() != nil {
			break
		}
		if seq > 0 {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				break
			case <-timer.C:
			}
			if ctx.Err() != nil {
				break
			}
		}
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		r := request(attemptCtx)
		cancel()
		responded := r.err == nil && r.status > 0
		outcome := "response"
		if r.err != nil {
			outcome = "error"
		}
		if responded {
			successes++
		} else {
			failures++
		}
		fmt.Printf("%s seq=%d status=%d bytes=%d duration=%s error=%v\n", time.Now().UTC().Format(time.RFC3339Nano), seq, r.status, r.bytes, time.Since(start).Round(time.Millisecond), r.err)
		var detail any
		if r.err != nil {
			detail = map[string]any{"kind": errorKind(r.err), "message": r.err.Error()}
		}
		journal.Event("probe_attempt", outcome, time.Since(start), "seq", seq, "status", r.status, "bytes", r.bytes, "error", detail, "family", r.family, "local", r.local, "remote", r.remote, "dnsMs", r.dnsMs, "connectMs", r.connectMs, "tlsMs", r.tlsMs, "firstByteMs", r.firstByteMs)
		if seq > 0 && everResponded && responded != lastResponded {
			if responded {
				fmt.Println("Ответы возобновились")
				journal.Event("responses_resumed", "observed", 0, "seq", seq)
			} else {
				fmt.Println("Ответы прекратились")
				journal.Event("responses_stopped", "observed", 0, "seq", seq)
			}
		}
		if responded {
			everResponded = true
		}
		lastResponded = responded
	}
	fmt.Printf("Итог наблюдений: ответов=%d ошибок=%d\n", successes, failures)
	journal.Event("probe_summary", "observed", 0, "successes", successes, "failures", failures, "attempted", successes+failures, "requested", count, "complete", count > 0 && successes+failures == count, "cancelled", ctx.Err() != nil)
	return nil
}

func listenTCP(target string, count int, timeout time.Duration, journal *runlog.Log) error {
	l, err := net.Listen("tcp", target)
	if err != nil {
		return err
	}
	defer l.Close()
	fmt.Printf("listening %s\n", l.Addr())
	received := 0
	for received < count {
		if tcpListener, ok := l.(*net.TCPListener); ok {
			_ = tcpListener.SetDeadline(time.Now().Add(timeout))
		}
		c, err := l.Accept()
		if err != nil {
			return err
		}
		reader := bufio.NewReaderSize(c, 256)
		for received < count {
			_ = c.SetDeadline(time.Now().Add(timeout))
			lineBytes, err := reader.ReadSlice('\n')
			if err != nil {
				break
			}
			line := string(lineBytes)
			if len(line) > 256 || !validMarker(line) {
				break
			}
			fmt.Printf("from=%s marker_valid=true\n", c.RemoteAddr())
			if _, err := c.Write([]byte("ack " + line)); err != nil {
				break
			}
			journal.Event("listener_reply", "ack_sent", 0, "seq", received, "remote", c.RemoteAddr().String(), "bytes", len(line))
			received++
		}
		_ = c.Close()
	}
	return nil
}

func listenUDP(target string, count int, timeout time.Duration, journal *runlog.Log) error {
	a, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		return err
	}
	defer c.Close()
	fmt.Printf("listening %s\n", c.LocalAddr())
	buf := make([]byte, 512)
	for i := 0; i < count; i++ {
		_ = c.SetDeadline(time.Now().Add(timeout))
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if !validMarker(string(buf[:n])) {
			return errors.New("invalid marker")
		}
		fmt.Printf("from=%s marker_valid=true\n", from)
		if _, err := c.WriteToUDP(append([]byte("ack "), buf[:n]...), from); err != nil {
			return err
		}
		journal.Event("listener_reply", "ack_sent", 0, "seq", i, "remote", from.String(), "bytes", n)
	}
	return nil
}

func hold(mode, target string, count int, interval, timeout time.Duration, id string, journal *runlog.Log) error {
	network := "tcp"
	if mode == "udp-hold" {
		network = "udp"
	}
	c, err := net.DialTimeout(network, target, timeout)
	if err != nil {
		return err
	}
	defer c.Close()
	for i := 0; i < count; i++ {
		if i > 0 {
			time.Sleep(interval)
		}
		marker := fmt.Sprintf("kill-switch-probe %s %d %s\n", id, i, time.Now().UTC().Format(time.RFC3339Nano))
		attemptStarted := time.Now()
		if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		_, err = c.Write([]byte(marker))
		if err == nil {
			if network == "tcp" {
				err = readTCPAck(c, marker)
			} else {
				err = readUDPAck(c.(*net.UDPConn), target, marker)
			}
		}
		fmt.Printf("%s seq=%d error=%v\n", time.Now().UTC().Format(time.RFC3339Nano), i, err)
		outcome := "ack_confirmed"
		if err != nil {
			outcome = "error"
		}
		var detail any
		if err != nil {
			detail = map[string]any{"kind": errorKind(err), "message": err.Error()}
		}
		journal.Event("probe_attempt", outcome, time.Since(attemptStarted), "seq", i, "error", detail, "local", c.LocalAddr().String(), "remote", c.RemoteAddr().String())
		if err != nil {
			return err
		}
	}
	return nil
}

func tcp(target, marker string, timeout time.Duration) error {
	c, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := c.Write([]byte(marker)); err != nil {
		return err
	}
	return readTCPAck(c, marker)
}

func udp(target, marker string, timeout time.Duration, connected bool) error {
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	var c *net.UDPConn
	if connected {
		c, err = net.DialUDP("udp", nil, addr)
	} else {
		c, err = net.ListenUDP("udp", nil)
	}
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if connected {
		_, err = c.Write([]byte(marker))
	} else {
		_, err = c.WriteToUDP([]byte(marker), addr)
	}
	if err != nil {
		return err
	}
	return readUDPAck(c, target, marker)
}

func readTCPAck(c net.Conn, marker string) error {
	reader := bufio.NewReaderSize(c, 256)
	lineBytes, err := reader.ReadSlice('\n')
	if err != nil {
		return err
	}
	line := string(lineBytes)
	if len(line) > 256 || line != "ack "+marker {
		return errors.New("ACK does not match marker")
	}
	fmt.Println("ACK подтверждён")
	return nil
}

func readUDPAck(c *net.UDPConn, target, marker string) error {
	buf := make([]byte, 512)
	n, from, err := c.ReadFromUDP(buf)
	if err != nil {
		return err
	}
	want, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	if from == nil || !from.IP.Equal(want.IP) || from.Port != want.Port {
		return errors.New("ACK from unexpected sender")
	}
	if string(buf[:n]) != "ack "+marker {
		return errors.New("ACK does not match marker")
	}
	fmt.Println("ACK подтверждён")
	return nil
}

func validMarker(line string) bool {
	if len(line) > 256 || !strings.HasSuffix(line, "\n") {
		return false
	}
	parts := strings.Fields(line)
	if len(parts) != 4 || parts[0] != "kill-switch-probe" || len(parts[1]) != 16 {
		return false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return false
	}
	if _, err := strconv.Atoi(parts[2]); err != nil {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, parts[3])
	return err == nil
}

func dns(name string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, name)
	if err == nil {
		fmt.Printf("answers=%v\n", addrs)
	}
	return err
}
