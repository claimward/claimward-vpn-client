// Package buildinfo carries version metadata injected at build time via -ldflags.
package buildinfo

// Version is set with -ldflags "-X .../buildinfo.Version=v1.2.3". Defaults to "dev".
var Version = "dev"

// Commit is the short git SHA, set the same way.
var Commit = "none"
