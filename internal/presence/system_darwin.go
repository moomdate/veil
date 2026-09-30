//go:build darwin && cgo

package presence

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>

static int veil_can_confirm(void) {
	LAContext *ctx = [[LAContext alloc] init];
	return [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:nil] ? 1 : 0;
}

// veil_confirm returns 1 if the user confirmed, 0 if not, and -1 if
// nobody answered within timeout_sec (the prompt is then dismissed).
static int veil_confirm(const char *reason, int timeout_sec) {
	LAContext *ctx = [[LAContext alloc] init];
	NSString *why = [NSString stringWithUTF8String:reason];
	dispatch_semaphore_t done = dispatch_semaphore_create(0);
	__block int ok = 0;
	[ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
	    localizedReason:why
	              reply:^(BOOL success, NSError *error) {
		ok = success ? 1 : 0;
		dispatch_semaphore_signal(done);
	}];
	if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_sec * NSEC_PER_SEC)) != 0) {
		[ctx invalidate];
		return -1;
	}
	return ok;
}
*/
import "C"

import (
	"sync"
	"unsafe"
)

// System confirms presence with Touch ID or the login password.
type System struct{ mu sync.Mutex }

func (*System) Available() bool { return C.veil_can_confirm() == 1 }

func (s *System) Confirm(reason string) error {
	// One prompt at a time; a second request waits for the first answer.
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.Available() {
		return ErrUnavailable
	}
	cr := C.CString(reason)
	defer C.free(unsafe.Pointer(cr))
	switch C.veil_confirm(cr, C.int(Timeout.Seconds())) {
	case 1:
		return nil
	case -1:
		return ErrTimedOut
	}
	return ErrCanceled
}
