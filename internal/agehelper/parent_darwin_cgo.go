//go:build darwin && cgo

package agehelper

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <libproc.h>
#include <stdint.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/types.h>
#include <unistd.h>

#define YT_CODE_HASH_MAX 64

typedef struct {
	uint32_t pid;
	uint32_t ppid;
	uint32_t uid;
	uint32_t ruid;
	uint64_t start_sec;
	uint64_t start_usec;
	uint32_t flags;
	uint32_t signature_flags;
	char path[PROC_PIDPATHINFO_MAXSIZE];
	uint8_t code_hash[YT_CODE_HASH_MAX];
	CFIndex code_hash_len;
} YTProcessIdentity;

static int YTUnsafeEntitlement(CFDictionaryRef signing, CFStringRef key) {
	CFTypeRef entitlements_value = CFDictionaryGetValue(signing, kSecCodeInfoEntitlementsDict);
	if (entitlements_value == NULL || CFGetTypeID(entitlements_value) != CFDictionaryGetTypeID()) {
		return 0;
	}
	CFTypeRef value = CFDictionaryGetValue((CFDictionaryRef)entitlements_value, key);
	return value != NULL && CFGetTypeID(value) == CFBooleanGetTypeID() &&
		CFBooleanGetValue((CFBooleanRef)value);
}

static int YTCodeHash(
	pid_t pid,
	uint8_t *output,
	CFIndex *output_len,
	uint32_t *signature_flags
) {
	int process = (int)pid;
	CFNumberRef pid_number = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &process);
	if (pid_number == NULL) {
		return 0;
	}
	const void *keys[] = {kSecGuestAttributePid};
	const void *values[] = {pid_number};
	CFDictionaryRef attributes = CFDictionaryCreate(
		kCFAllocatorDefault,
		keys,
		values,
		1,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	if (attributes == NULL) {
		CFRelease(pid_number);
		return 0;
	}

	SecCodeRef code = NULL;
	CFDictionaryRef signing = NULL;
	OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
	if (status == errSecSuccess && code != NULL) {
		status = SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL);
	}
	if (status == errSecSuccess) {
		status = SecCodeCopySigningInformation(
			code,
			kSecCSSigningInformation | kSecCSDynamicInformation,
			&signing
		);
	}
	int valid = 0;
	if (status == errSecSuccess && signing != NULL) {
		CFTypeRef hash_value = CFDictionaryGetValue(signing, kSecCodeInfoUnique);
		CFTypeRef flags_value = CFDictionaryGetValue(signing, kSecCodeInfoFlags);
		CFTypeRef status_value = CFDictionaryGetValue(signing, kSecCodeInfoStatus);
		uint32_t flags = 0;
		uint32_t process_status = 0;
		if (flags_value != NULL && CFGetTypeID(flags_value) == CFNumberGetTypeID()) {
			CFNumberGetValue((CFNumberRef)flags_value, kCFNumberSInt32Type, &flags);
		}
		if (status_value != NULL && CFGetTypeID(status_value) == CFNumberGetTypeID()) {
			CFNumberGetValue((CFNumberRef)status_value, kCFNumberSInt32Type, &process_status);
		}
		const uint32_t required_status =
			kSecCodeStatusValid | kSecCodeStatusHard | kSecCodeStatusKill;
		if ((flags & kSecCodeSignatureRuntime) != 0 &&
			(process_status & required_status) == required_status &&
			(process_status & kSecCodeStatusDebugged) == 0 &&
			!YTUnsafeEntitlement(signing, CFSTR("com.apple.security.cs.allow-dyld-environment-variables")) &&
			!YTUnsafeEntitlement(signing, CFSTR("com.apple.security.get-task-allow")) &&
			hash_value != NULL && CFGetTypeID(hash_value) == CFDataGetTypeID()) {
			CFDataRef hash = (CFDataRef)hash_value;
			CFIndex length = CFDataGetLength(hash);
			if (length > 0 && length <= YT_CODE_HASH_MAX) {
				CFDataGetBytes(hash, CFRangeMake(0, length), output);
				*output_len = length;
				*signature_flags = flags;
				valid = 1;
			}
		}
	}
	if (signing != NULL) {
		CFRelease(signing);
	}
	if (code != NULL) {
		CFRelease(code);
	}
	CFRelease(attributes);
	CFRelease(pid_number);
	return valid;
}

static int YTSnapshot(pid_t pid, YTProcessIdentity *output) {
	memset(output, 0, sizeof(*output));
	struct proc_bsdinfo info;
	memset(&info, 0, sizeof(info));
	int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
	if (count != sizeof(info) || info.pbi_pid != (uint32_t)pid) {
		return 0;
	}
	if ((info.pbi_flags & (PROC_FLAG_TRACED | PROC_FLAG_INEXIT | PROC_FLAG_PSUGID)) != 0) {
		return 0;
	}
	int path_length = proc_pidpath(pid, output->path, sizeof(output->path));
	if (path_length <= 0 || path_length >= sizeof(output->path) || output->path[0] != '/') {
		return 0;
	}
	output->path[sizeof(output->path) - 1] = '\0';
	if (!YTCodeHash(
		pid,
		output->code_hash,
		&output->code_hash_len,
		&output->signature_flags
	)) {
		return 0;
	}
	output->pid = info.pbi_pid;
	output->ppid = info.pbi_ppid;
	output->uid = info.pbi_uid;
	output->ruid = info.pbi_ruid;
	output->start_sec = info.pbi_start_tvsec;
	output->start_usec = info.pbi_start_tvusec;
	output->flags = info.pbi_flags;
	return 1;
}

static int YTSameInstance(const YTProcessIdentity *left, const YTProcessIdentity *right) {
	return left->pid == right->pid &&
		left->ppid == right->ppid &&
		left->uid == right->uid &&
		left->ruid == right->ruid &&
		left->start_sec == right->start_sec &&
		left->start_usec == right->start_usec &&
		left->signature_flags == right->signature_flags &&
		left->code_hash_len == right->code_hash_len &&
		strcmp(left->path, right->path) == 0 &&
		memcmp(left->code_hash, right->code_hash, left->code_hash_len) == 0;
}

static int YTVerifyParentProcess(void) {
	pid_t self_pid = getpid();
	pid_t parent_pid = getppid();
	if (self_pid <= 1 || parent_pid <= 1 || parent_pid == self_pid) {
		return 0;
	}
	YTProcessIdentity before;
	YTProcessIdentity self;
	YTProcessIdentity after;
	if (!YTSnapshot(parent_pid, &before) ||
		!YTSnapshot(self_pid, &self) ||
		!YTSnapshot(parent_pid, &after)) {
		return 0;
	}
	if (getppid() != parent_pid || self.ppid != (uint32_t)parent_pid ||
		!YTSameInstance(&before, &after)) {
		return 0;
	}
	if (before.uid != (uint32_t)geteuid() || before.ruid != (uint32_t)getuid() ||
		self.uid != (uint32_t)geteuid() || self.ruid != (uint32_t)getuid()) {
		return 0;
	}
	if (strcmp(before.path, self.path) != 0 ||
		before.code_hash_len != self.code_hash_len ||
		memcmp(before.code_hash, self.code_hash, before.code_hash_len) != 0) {
		return 0;
	}
	memset(&before, 0, sizeof(before));
	memset(&self, 0, sizeof(self));
	memset(&after, 0, sizeof(after));
	return 1;
}
*/
import "C"

import "errors"

func verifyParentProcess() error {
	if C.YTVerifyParentProcess() != 1 {
		return errors.New("age helper parent is not authorized")
	}
	return nil
}

func parentVerificationSupported() bool { return true }
