//go:build !windows

package wgtun

// tunName is the interface name asked of the kernel: "utun" lets macOS pick
// the next free utunN.
const tunName = "utun"
