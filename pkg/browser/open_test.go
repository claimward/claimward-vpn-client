package browser

import (
	"errors"
	"strings"
	"testing"
)

func TestOpenSpawnsTheOpenerForHTTPSOnly(t *testing.T) {
	var got [][]string
	old := start
	start = func(name string, args ...string) error {
		got = append(got, append([]string{name}, args...))
		return nil
	}
	t.Cleanup(func() { start = old })

	for _, u := range []string{"https://idp.example.org/device?code=AB-CD", "http://127.0.0.1:8080/cb"} {
		if err := Open(u); err != nil {
			t.Errorf("Open(%q) = %v", u, err)
		}
	}
	if len(got) != 2 || got[0][len(got[0])-1] != "https://idp.example.org/device?code=AB-CD" {
		t.Fatalf("spawned %v", got)
	}
	got = nil
	for _, u := range []string{
		"", "-a Calculator", "--help", "file:///etc/passwd", "javascript:alert(1)", "ms-msdt:/id", "\\\\host\\share\\x",
		"//host/x", "https://", "http:///x", "https://a\nb", "ftp://example.org/x",
	} {
		if err := Open(u); err == nil {
			t.Errorf("Open(%q) spawned the opener", u)
		}
	}
	if len(got) != 0 {
		t.Fatalf("a refused URL reached the opener: %v", got)
	}
}

func TestOpenReportsAnOpenerThatCannotStart(t *testing.T) {
	old := start
	start = func(string, ...string) error { return errors.New("boom") }
	t.Cleanup(func() { start = old })
	if err := Open("https://example.org"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
}
