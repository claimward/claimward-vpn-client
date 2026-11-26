package helper

// DefaultApprovalsPath is where the approved servers are kept: beside the
// socket, in the directory whose protected ACL (dirSDDL) leaves only SYSTEM
// and the Administrators the right to write, and which a file created in it
// inherits.
const DefaultApprovalsPath = `C:\ProgramData\Claimward\approved-servers.json`
