//go:build darwin && cgo

package keystore

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>

static CFStringRef veil_str(const char *s) {
	return CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
}

// veil_save stores data as a generic password whose access list trusts only
// the running executable. Any other program that asks for it makes macOS
// show a dialog to the user. The Keychain Services calls used here are
// deprecated but are the only way to set a per-application access list
// without an Apple-issued entitlement.
static OSStatus veil_save(const char *service, const char *account, const void *data, long len) {
	SecTrustedApplicationRef self = NULL;
	OSStatus st = SecTrustedApplicationCreateFromPath(NULL, &self);
	if (st != errSecSuccess) return st;

	CFArrayRef apps = CFArrayCreate(NULL, (const void **)&self, 1, &kCFTypeArrayCallBacks);
	CFStringRef label = veil_str("Veil master key");
	SecAccessRef access = NULL;
	st = SecAccessCreate(label, apps, &access);
	CFRelease(apps);
	CFRelease(self);
	if (st != errSecSuccess) { CFRelease(label); return st; }

	CFStringRef svc = veil_str(service), acct = veil_str(account);
	CFDataRef value = CFDataCreate(NULL, data, len);
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(q, kSecAttrService, svc);
	CFDictionarySetValue(q, kSecAttrAccount, acct);
	CFDictionarySetValue(q, kSecAttrLabel, label);
	CFDictionarySetValue(q, kSecValueData, value);
	CFDictionarySetValue(q, kSecAttrAccess, access);
	st = SecItemAdd(q, NULL);

	CFRelease(q); CFRelease(value); CFRelease(acct); CFRelease(svc); CFRelease(label); CFRelease(access);
	return st;
}

static CFMutableDictionaryRef veil_query(const char *service, const char *account) {
	CFStringRef svc = veil_str(service), acct = veil_str(account);
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(q, kSecAttrService, svc);
	CFDictionarySetValue(q, kSecAttrAccount, acct);
	CFRelease(svc); CFRelease(acct);
	return q;
}

// veil_load copies the item's data into buf. *n is the buffer size on
// input and the data length on output.
static OSStatus veil_load(const char *service, const char *account, void *buf, long *n) {
	CFMutableDictionaryRef q = veil_query(service, account);
	CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef out = NULL;
	OSStatus st = SecItemCopyMatching(q, &out);
	CFRelease(q);
	if (st != errSecSuccess) return st;
	long len = CFDataGetLength((CFDataRef)out);
	if (len > *n) { CFRelease(out); return errSecBufferTooSmall; }
	CFDataGetBytes((CFDataRef)out, CFRangeMake(0, len), buf);
	*n = len;
	CFRelease(out);
	return errSecSuccess;
}

// veil_hardened reports whether the running executable is signed with the
// hardened runtime, which stops other programs injecting code into it.
static int veil_hardened(void) {
	SecCodeRef self = NULL;
	if (SecCodeCopySelf(kSecCSDefaultFlags, &self) != errSecSuccess) return -1;
	SecStaticCodeRef stat = NULL;
	OSStatus st = SecCodeCopyStaticCode(self, kSecCSDefaultFlags, &stat);
	CFRelease(self);
	if (st != errSecSuccess) return -1;
	CFDictionaryRef info = NULL;
	st = SecCodeCopySigningInformation(stat, kSecCSDynamicInformation, &info);
	CFRelease(stat);
	if (st != errSecSuccess) return -1;
	int hardened = 0;
	CFNumberRef flags = CFDictionaryGetValue(info, kSecCodeInfoFlags);
	uint32_t f = 0;
	if (flags && CFNumberGetValue(flags, kCFNumberSInt32Type, &f)) hardened = (f & kSecCodeSignatureRuntime) != 0;
	CFRelease(info);
	return hardened;
}

static OSStatus veil_delete(const char *service, const char *account) {
	CFMutableDictionaryRef q = veil_query(service, account);
	OSStatus st = SecItemDelete(q);
	CFRelease(q);
	return st;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// AppOnly reports whether the stored key can be read only by Veil itself.
// On macOS the Keychain item's access list trusts only the Veil binary, so
// any other program that asks for it makes macOS ask the user first.
const AppOnly = true

// ErrUnprotected means this copy of Veil isn't signed with the hardened
// runtime, so another program could inject code into it and read the key.
var ErrUnprotected = errors.New("this copy of Veil isn't protected against code injection yet; run `veil protect` to fix it")

// Hardened reports whether the running binary is signed with the hardened
// runtime.
func Hardened() bool { return C.veil_hardened() == 1 }

// OS stores the key in the macOS login Keychain, readable only by Veil.
type OS struct {
	Service string // keychain service name, e.g. "veil"
	Account string // keychain account, e.g. the vault path

	// RequireHardened refuses to touch the key from a binary that isn't
	// signed with the hardened runtime. The real CLI sets it; tests don't.
	RequireHardened bool
}

func (s OS) check() error {
	if s.RequireHardened && !Hardened() {
		return ErrUnprotected
	}
	return nil
}

func (s OS) Load() ([]byte, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	svc, acct := C.CString(s.Service), C.CString(s.Account)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))

	buf := make([]byte, 256)
	n := C.long(len(buf))
	st := C.veil_load(svc, acct, unsafe.Pointer(&buf[0]), &n)
	if err := statusErr(st, "read master key from the Keychain"); err != nil {
		return nil, err
	}
	key := append([]byte(nil), buf[:n]...)
	clear(buf)
	if len(key) != KeySize {
		return nil, errors.New("the master key in the Keychain is damaged")
	}
	return key, nil
}

func (s OS) Save(key []byte) error {
	if len(key) != KeySize {
		return fmt.Errorf("master key must be %d bytes", KeySize)
	}
	if err := s.check(); err != nil {
		return err
	}
	svc, acct := C.CString(s.Service), C.CString(s.Account)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	st := C.veil_save(svc, acct, unsafe.Pointer(&key[0]), C.long(len(key)))
	return statusErr(st, "save master key to the Keychain")
}

func (s OS) Delete() error {
	svc, acct := C.CString(s.Service), C.CString(s.Account)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	st := C.veil_delete(svc, acct)
	if st == C.errSecItemNotFound {
		return nil
	}
	return statusErr(st, "delete master key from the Keychain")
}

func statusErr(st C.OSStatus, action string) error {
	switch st {
	case C.errSecSuccess:
		return nil
	case C.errSecItemNotFound:
		return ErrNotFound
	case C.errSecUserCanceled, C.errSecAuthFailed, C.errSecInteractionNotAllowed:
		return fmt.Errorf("%s: %w. If you just updated Veil, run the command again and choose Always Allow", action, ErrDenied)
	case C.errSecDuplicateItem:
		return fmt.Errorf("%s: a key for this vault already exists in the Keychain", action)
	}
	msg := C.SecCopyErrorMessageString(st, nil)
	if msg == 0 {
		return fmt.Errorf("%s: OSStatus %d", action, int(st))
	}
	defer C.CFRelease(C.CFTypeRef(msg))
	buf := make([]byte, 512)
	C.CFStringGetCString(msg, (*C.char)(unsafe.Pointer(&buf[0])), C.CFIndex(len(buf)), C.kCFStringEncodingUTF8)
	return fmt.Errorf("%s: %s", action, C.GoString((*C.char)(unsafe.Pointer(&buf[0]))))
}
