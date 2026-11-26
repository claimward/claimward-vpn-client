//go:build !darwin && !linux && !windows

package helper

// DefaultApprovalsPath is where the approved servers are kept: a directory
// only root writes.
const DefaultApprovalsPath = "/var/db/claimward/approved-servers.json"
