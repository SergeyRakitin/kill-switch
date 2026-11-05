package runlog

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultMaxFile = 10 << 20
const defaultMaxBudget = 100 << 20

type Log struct {
	mu                                 sync.Mutex
	file                               *os.File
	logger                             *slog.Logger
	dir, component, runID, operationID string
	part                               int
	maxFile, maxBudget                 int64
	retention                          time.Duration
	level                              string
	writeErr                           error
	failed                             bool
}

type fileWriter struct{ log *Log }

func (w fileWriter) Write(p []byte) (int, error) {
	n, err := w.log.file.Write(p)
	w.log.writeErr = err
	return n, err
}

func envPositive(name string, fallback int64) int64 {
	v, err := strconv.ParseInt(os.Getenv(name), 10, 64)
	if err != nil || v < 1 || v > 4096 {
		return fallback
	}
	return v
}

func New(component, dir, level, operationID, runID string) (*Log, error) {
	if runID == "" {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		runID = hex.EncodeToString(b[:])
	}
	if dir == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(filepath.Dir(exe), "logs")
	}
	l := &Log{dir: dir, component: component, runID: runID, operationID: operationID, level: level,
		maxFile: envPositive("KS_LOG_MAX_MIB", 10) << 20, maxBudget: envPositive("KS_LOG_BUDGET_MIB", 100) << 20,
		retention: time.Duration(envPositive("KS_LOG_RETENTION_DAYS", 7)) * 24 * time.Hour}
	if l.maxFile > l.maxBudget {
		l.maxFile = l.maxBudget
	}
	if err := l.open(level); err != nil {
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			return nil, err
		}
		fallback := filepath.Join(localAppData, "KillSwitch", "logs")
		if fallback == dir {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "%s log path unavailable (%v); using %s\n", component, err, fallback)
		l.dir = fallback
		if err := l.open(level); err != nil {
			return nil, err
		}
	}
	l.Event("run_start", "started", 0)
	return l, nil
}

func (l *Log) open(level string) error {
	if err := os.MkdirAll(l.dir, 0700); err != nil {
		return err
	}
	l.prune()
	name := fmt.Sprintf("%s-%s-%d-%s-%02d.jsonl", l.component, time.Now().UTC().Format("20060102T150405.000000000Z"), os.Getpid(), l.runID, l.part)
	f, err := os.OpenFile(filepath.Join(l.dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	l.file = f
	var lev slog.Level = slog.LevelInfo
	if strings.EqualFold(level, "debug") {
		lev = slog.LevelDebug
	}
	l.logger = slog.New(slog.NewJSONHandler(fileWriter{l}, &slog.HandlerOptions{Level: lev, ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			a.Value = slog.TimeValue(a.Value.Time().UTC())
		}
		return a
	}}))
	return nil
}

func (l *Log) prune() {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}
	type item struct {
		path string
		mod  time.Time
		size int64
	}
	var done []item
	var total int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), l.component+"-") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		total += info.Size()
		if strings.HasSuffix(e.Name(), ".done.jsonl") {
			done = append(done, item{filepath.Join(l.dir, e.Name()), info.ModTime(), info.Size()})
		}
	}
	sort.Slice(done, func(i, j int) bool { return done[i].mod.Before(done[j].mod) })
	for _, f := range done {
		if total <= l.maxBudget && time.Since(f.mod) < l.retention {
			break
		}
		if os.Remove(f.path) == nil {
			total -= f.size
		}
	}
}

func (l *Log) budgetUsed() int64 {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return l.maxBudget
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), l.component+"-") || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		info, err := e.Info()
		if err == nil {
			total += info.Size()
		}
	}
	return total
}

func (l *Log) Event(event, outcome string, duration time.Duration, attrs ...any) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed || l.file == nil {
		return
	}
	info, err := l.file.Stat()
	if err != nil {
		l.failed = true
		fmt.Fprintln(os.Stderr, "log stat:", err)
		return
	}
	if info.Size() >= l.maxFile {
		l.rotate()
	}
	if l.failed || l.file == nil {
		return
	}
	if l.budgetUsed() >= l.maxBudget {
		l.failed = true
		fmt.Fprintln(os.Stderr, "log budget exhausted; recording stopped")
		return
	}
	base := []any{"component", l.component, "buildVersion", "dev", "pid", os.Getpid(), "runId", l.runID, "operationId", l.operationID, "event", event, "outcome", outcome, "durationMs", duration.Milliseconds()}
	base = append(base, attrs...)
	l.logger.Info(event, base...)
	if l.writeErr != nil {
		l.failed = true
		fmt.Fprintln(os.Stderr, "log write:", l.writeErr)
		return
	}
	if err := l.file.Sync(); err != nil {
		l.failed = true
		fmt.Fprintln(os.Stderr, "log write:", err)
	}
}

func (l *Log) rotate() {
	if err := l.finishFile(); err != nil {
		l.failed = true
		fmt.Fprintln(os.Stderr, "log rotate:", err)
		return
	}
	l.part++
	if err := l.open(l.level); err != nil {
		l.failed = true
		fmt.Fprintln(os.Stderr, "log rotate:", err)
	}
}

func (l *Log) finishFile() error {
	if l.file == nil {
		return nil
	}
	name := l.file.Name()
	err := l.file.Close()
	l.file = nil
	if err != nil {
		return err
	}
	return os.Rename(name, strings.TrimSuffix(name, ".jsonl")+".done.jsonl")
}

func (l *Log) Close(outcome string, duration time.Duration) {
	if l == nil {
		return
	}
	l.Event("run_end", outcome, duration)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.finishFile(); err != nil {
		fmt.Fprintln(os.Stderr, "log close:", err)
	}
}

func (l *Log) Path() string {
	if l == nil {
		return ""
	}
	return l.dir
}
func (l *Log) RunID() string {
	if l == nil {
		return ""
	}
	return l.runID
}
