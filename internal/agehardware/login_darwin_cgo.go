//go:build darwin && cgo

package agehardware

/*
#cgo LDFLAGS: -ldl

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#define YUBITOUCH_CKR_GENERAL_ERROR 0x00000005UL
#define YUBITOUCH_CKR_ARGUMENTS_BAD 0x00000007UL

typedef unsigned long yubitouch_ck_rv;
typedef unsigned long yubitouch_ck_ulong;
typedef unsigned long yubitouch_ck_session_handle;
typedef unsigned long yubitouch_ck_user_type;
typedef unsigned char yubitouch_ck_byte;
typedef yubitouch_ck_rv (*yubitouch_login_fn)(
	yubitouch_ck_session_handle,
	yubitouch_ck_user_type,
	yubitouch_ck_byte *,
	yubitouch_ck_ulong
);

static void yubitouch_wipe(void *value, size_t length) {
	volatile unsigned char *cursor = (volatile unsigned char *)value;
	while (length-- > 0) {
		*cursor++ = 0;
	}
}

static yubitouch_ck_rv yubitouch_login_bytes(
	const char *provider,
	yubitouch_ck_session_handle session,
	yubitouch_ck_user_type user,
	const yubitouch_ck_byte *pin,
	yubitouch_ck_ulong pin_length
) {
	if (provider == NULL || pin == NULL || pin_length == 0) {
		return YUBITOUCH_CKR_ARGUMENTS_BAD;
	}
	void *handle = dlopen(provider, RTLD_NOW | RTLD_LOCAL);
	if (handle == NULL) {
		return YUBITOUCH_CKR_GENERAL_ERROR;
	}
	yubitouch_login_fn login = (yubitouch_login_fn)dlsym(handle, "C_Login");
	if (login == NULL) {
		dlclose(handle);
		return YUBITOUCH_CKR_GENERAL_ERROR;
	}
	yubitouch_ck_byte *pin_copy = (yubitouch_ck_byte *)malloc((size_t)pin_length);
	if (pin_copy == NULL) {
		dlclose(handle);
		return YUBITOUCH_CKR_GENERAL_ERROR;
	}
	memcpy(pin_copy, pin, (size_t)pin_length);
	yubitouch_ck_rv result = login(session, user, pin_copy, pin_length);
	yubitouch_wipe(pin_copy, (size_t)pin_length);
	free(pin_copy);
	dlclose(handle);
	return result;
}
*/
import "C"

import (
	"runtime"
	"unsafe"

	"github.com/miekg/pkcs11"
)

func secureLoginBytes(provider string, session pkcs11.SessionHandle, user uint, pin []byte) error {
	if provider == "" || len(pin) == 0 {
		return pkcs11.Error(pkcs11.CKR_ARGUMENTS_BAD)
	}
	providerValue := C.CString(provider)
	if providerValue == nil {
		return pkcs11.Error(pkcs11.CKR_HOST_MEMORY)
	}
	defer C.free(unsafe.Pointer(providerValue))
	result := C.yubitouch_login_bytes(
		providerValue,
		C.yubitouch_ck_session_handle(session),
		C.yubitouch_ck_user_type(user),
		(*C.yubitouch_ck_byte)(unsafe.Pointer(&pin[0])),
		C.yubitouch_ck_ulong(len(pin)),
	)
	runtime.KeepAlive(pin)
	if result != 0 {
		return pkcs11.Error(result)
	}
	return nil
}
