//go:build windows

package hproto

// DefaultSocketPath is where the privileged helper listens: an AF_UNIX
// socket (Windows 10 1803 and later) under ProgramData, whose directory ACL
// decides who may reach it.
const DefaultSocketPath = `C:\ProgramData\Claimward\helper.sock`
