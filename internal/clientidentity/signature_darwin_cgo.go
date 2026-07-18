//go:build darwin && cgo

package clientidentity

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static int YTCodeSignatureValid(int pid) {
    CFNumberRef pidNumber = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &pid);
    if (pidNumber == NULL) {
        return 0;
    }
    const void *keys[] = {kSecGuestAttributePid};
    const void *values[] = {pidNumber};
    CFDictionaryRef attributes = CFDictionaryCreate(
        kCFAllocatorDefault,
        keys,
        values,
        1,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    if (attributes == NULL) {
        CFRelease(pidNumber);
        return 0;
    }
    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
    if (status == errSecSuccess && code != NULL) {
        status = SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL);
    }
    if (code != NULL) {
        CFRelease(code);
    }
    CFRelease(attributes);
    CFRelease(pidNumber);
    return status == errSecSuccess;
}
*/
import "C"

func codeSignatureValid(pid int) bool {
	return C.YTCodeSignatureValid(C.int(pid)) != 0
}
