//go:build !windows && !linux

package wgtun

// InterfaceName is the name asked of the kernel: "utun" lets macOS pick the
// next free utunN, so every tunnel gets its own whatever the key.
func InterfaceName(string) string { return "utun" }

// removeStale: macOS numbers the interface itself; nothing can be stale.
func removeStale(string) error { return nil }
