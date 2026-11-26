package discovery

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
)

const bombChild = "CLAIMWARD_DISCOVERY_BOMB_CHILD"

// TestBombsAreRefusedUnderAMemoryLimit runs the bombs in a child process under
// GOMEMLIMIT and, where the platform enforces it, ulimit -v: a server that
// sends a document or a logo without end, or a deeply nested one, is refused,
// and the client's allocation stays far under what was offered. (Bomb tests
// assert a refusal; they never run against the host's whole memory.)
func TestBombsAreRefusedUnderAMemoryLimit(t *testing.T) {
	if os.Getenv(bombChild) != "" {
		t.Skip("the child runs bombChild")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := `ulimit -v 4194304 2>/dev/null; exec "$0" -test.run '^TestBombChild$' -test.v`
	if runtime.GOOS == "darwin" {
		script = `exec "$0" -test.run '^TestBombChild$' -test.v` // RLIMIT_AS is not enforced on macOS
	}
	cmd := exec.Command("sh", "-c", script, exe)
	cmd.Env = append(os.Environ(), bombChild+"=1", "GOMEMLIMIT=96MiB", "GOGC=50")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bomb child failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("--- PASS: TestBombChild")) {
		t.Fatalf("the child ran nothing:\n%s", out)
	}
}

func TestBombChild(t *testing.T) {
	if os.Getenv(bombChild) == "" {
		t.Skip("run by TestBombsAreRefusedUnderAMemoryLimit")
	}
	const offered = int64(2 << 30) // 2 GiB, never sent in full
	endless := func(prefix string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			chunk := bytes.Repeat([]byte(" "), 64<<10)
			_, _ = w.Write([]byte(prefix))
			for sent := int64(0); sent < offered; sent += int64(len(chunk)) {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		}
	}
	nested := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("[", MaxDocumentBytes-1)))
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	for name, h := range map[string]http.HandlerFunc{
		"endless document":   endless(`{"version":2,"providers":[`),
		"endless whitespace": endless(``),
		"nested brackets":    nested,
	} {
		srv := httptest.NewServer(h)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cfg, err := New(nil).Refresh(ctx, srv.URL)
		cancel()
		srv.Close()
		if err == nil {
			t.Errorf("%s: accepted %+v", name, cfg)
		}
	}

	// An endless logo behind an honest document.
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.PathWellKnownConfiguration {
			_, _ = w.Write([]byte(`{"version":2,"providers":[{"id":"a","kind":"github","name":"G","github_client_id":"x"}],"logo":{"path":"/l.svg","sha256":"` + sum("x") + `"}}`))
			return
		}
		endless(`<svg xmlns="http://www.w3.org/2000/svg">`)(w, r)
	}))
	defer svr.Close()
	c := New(nil)
	cfg, err := c.Refresh(context.Background(), svr.URL)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := c.Logo(context.Background(), svr.URL, cfg); err == nil || b != nil {
		t.Errorf("an endless logo was taken: %d bytes, %v", len(b), err)
	}

	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Errorf("the client allocated %d MiB handling 4 bombs of %d GiB: not bounded", grew>>20, offered>>30)
	}
}
