//go:build darwin && cgo

package macauth

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#cgo CFLAGS: -Wno-deprecated-declarations
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <string.h>

static OSStatus cw_obtain(const char *right, const char *prompt, unsigned char *out) {
	AuthorizationRef ref = NULL;
	OSStatus st = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &ref);
	if (st != errAuthorizationSuccess) return st;
	AuthorizationItem item = {right, 0, NULL, 0};
	AuthorizationRights rights = {1, &item};
	AuthorizationItem env = {kAuthorizationEnvironmentPrompt, strlen(prompt), (void *)prompt, 0};
	AuthorizationEnvironment environment = {1, &env};
	AuthorizationFlags flags = kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights;
	st = AuthorizationCopyRights(ref, &rights, &environment, flags, NULL);
	if (st == errAuthorizationSuccess) {
		AuthorizationExternalForm ef;
		st = AuthorizationMakeExternalForm(ref, &ef);
		if (st == errAuthorizationSuccess) memcpy(out, ef.bytes, kAuthorizationExternalFormLength);
	}
	if (st != errAuthorizationSuccess) AuthorizationFree(ref, kAuthorizationFlagDestroyRights);
	// On success the authorization is deliberately left alive for the helper
	// to consume: it is destroyed by Verify.
	return st;
}

static OSStatus cw_verify(const unsigned char *form, const char *right) {
	AuthorizationExternalForm ef;
	memcpy(ef.bytes, form, kAuthorizationExternalFormLength);
	AuthorizationRef ref = NULL;
	OSStatus st = AuthorizationCreateFromExternalForm(&ef, &ref);
	if (st != errAuthorizationSuccess) return st;
	AuthorizationItem item = {right, 0, NULL, 0};
	AuthorizationRights rights = {1, &item};
	// No InteractionAllowed: the helper never shows a prompt; the right is
	// granted already, or it is refused.
	st = AuthorizationCopyRights(ref, &rights, kAuthorizationEmptyEnvironment, kAuthorizationFlagExtendRights, NULL);
	AuthorizationFree(ref, kAuthorizationFlagDestroyRights);
	return st;
}

static OSStatus cw_ensure(const char *right, const char *rule, const char *desc) {
	if (AuthorizationRightGet(right, NULL) == errAuthorizationSuccess) return errAuthorizationSuccess;
	AuthorizationRef ref = NULL;
	OSStatus st = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &ref);
	if (st != errAuthorizationSuccess) return st;
	CFStringRef r = CFStringCreateWithCString(NULL, rule, kCFStringEncodingUTF8);
	CFStringRef d = CFStringCreateWithCString(NULL, desc, kCFStringEncodingUTF8);
	st = AuthorizationRightSet(ref, right, r, d, NULL, NULL);
	CFRelease(r);
	CFRelease(d);
	AuthorizationFree(ref, kAuthorizationFlagDefaults);
	return st;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Obtain shows the system's authentication dialog, with prompt as its text,
// and returns the authorization's external form. Called by the app.
func Obtain(prompt string) ([]byte, error) {
	cr, cp := C.CString(Right), C.CString(prompt)
	defer C.free(unsafe.Pointer(cr))
	defer C.free(unsafe.Pointer(cp))
	out := make([]byte, FormLength)
	if st := C.cw_obtain(cr, cp, (*C.uchar)(unsafe.Pointer(&out[0]))); st != 0 {
		return nil, fmt.Errorf("authorization: OSStatus %d", int(st))
	}
	return out, nil
}

// Verify asks the system whether the token carries Right, and destroys the
// authorization. Called by the helper, as root.
func Verify(form []byte) error {
	if len(form) != FormLength {
		return fmt.Errorf("%w: an external form is %d bytes, got %d", ErrNotAuthorized, FormLength, len(form))
	}
	cr := C.CString(Right)
	defer C.free(unsafe.Pointer(cr))
	if st := C.cw_verify((*C.uchar)(unsafe.Pointer(&form[0])), cr); st != 0 {
		return fmt.Errorf("%w (OSStatus %d)", ErrNotAuthorized, int(st))
	}
	return nil
}

// EnsureRight creates Right in the policy database when it is not there.
// Called by the helper at start; needs root.
func EnsureRight() error {
	cr, cu, cd := C.CString(Right), C.CString(Rule), C.CString("Trust a VPN server")
	defer C.free(unsafe.Pointer(cr))
	defer C.free(unsafe.Pointer(cu))
	defer C.free(unsafe.Pointer(cd))
	if st := C.cw_ensure(cr, cu, cd); st != 0 {
		return fmt.Errorf("authorization right: OSStatus %d", int(st))
	}
	return nil
}
