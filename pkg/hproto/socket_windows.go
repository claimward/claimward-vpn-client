//go:build windows

package hproto

// DefaultSocketPath is where the privileged helper listens: an AF_UNIX
// socket (Windows 10 1803 and later) under ProgramData, whose directory ACL
// decides who may reach it.
const DefaultSocketPath = `C:\ProgramData\Claimward\helper.sock`

// DefaultElevatedSocketPath is the second socket of the helper, beside the
// first: only an elevated process (one whose token has the Administrators
// group enabled, which a UAC consent grants and a standard user's process
// cannot give itself) may connect to it. ActionApprove is accepted only here.
const DefaultElevatedSocketPath = `C:\ProgramData\Claimward\approve.sock`
