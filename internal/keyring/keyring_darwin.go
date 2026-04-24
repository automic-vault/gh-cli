//go:build darwin

package keyring

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

static OSStatus create_access_for_path(const char *path, CFStringRef descriptor, SecAccessRef *accessRef) {
	SecTrustedApplicationRef app = NULL;
	OSStatus status = SecTrustedApplicationCreateFromPath(path, &app);
	if (status != errSecSuccess) {
		return status;
	}

	const void *trustedApps[] = { app };
	CFArrayRef trustedList = CFArrayCreate(kCFAllocatorDefault, trustedApps, 1, &kCFTypeArrayCallBacks);
	status = SecAccessCreate(descriptor, trustedList, accessRef);
	CFRelease(trustedList);
	CFRelease(app);
	return status;
}

static OSStatus create_generic_password_item(
	const char *service, UInt32 serviceLen,
	const char *account, UInt32 accountLen,
	const char *label, UInt32 labelLen,
	const void *secret, UInt32 secretLen,
	SecAccessRef accessRef,
	SecKeychainItemRef *itemRef
) {
	SecKeychainAttribute attrs[3];
	attrs[0].tag = kSecServiceItemAttr;
	attrs[0].length = serviceLen;
	attrs[0].data = (void *)service;
	attrs[1].tag = kSecAccountItemAttr;
	attrs[1].length = accountLen;
	attrs[1].data = (void *)account;
	attrs[2].tag = kSecLabelItemAttr;
	attrs[2].length = labelLen;
	attrs[2].data = (void *)label;

	SecKeychainAttributeList attrList;
	attrList.count = 3;
	attrList.attr = attrs;

	return SecKeychainItemCreateFromContent(
		kSecGenericPasswordItemClass,
		&attrList,
		secretLen,
		secret,
		NULL,
		accessRef,
		itemRef
	);
}
*/
import "C"

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

const (
	encodingPrefix       = "go-keyring-encoded:"
	base64EncodingPrefix = "go-keyring-base64:"
	errSecItemNotFound   = -25300
)

func set(service, user, secret string) error {
	access, err := trustedApplicationAccess(service)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(access))

	status := createGenericPasswordItem(service, user, secret, access)
	if status != C.errSecDuplicateItem {
		return keychainError(status)
	}
	if err := deleteSecret(service, user); err != nil {
		return err
	}
	return keychainError(createGenericPasswordItem(service, user, secret, access))
}

func get(service, user string) (string, error) {
	query := itemQuery(service, user)
	defer C.CFRelease(C.CFTypeRef(query))

	C.CFDictionarySetValue(
		query,
		unsafe.Pointer(C.kSecReturnData),
		unsafe.Pointer(C.kCFBooleanTrue),
	)
	C.CFDictionarySetValue(
		query,
		unsafe.Pointer(C.kSecMatchLimit),
		unsafe.Pointer(C.kSecMatchLimitOne),
	)

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query), &result)
	if err := keychainError(status); err != nil {
		return "", err
	}
	defer C.CFRelease(result)

	secret := bytes(C.CFDataRef(result))
	return decode(secret)
}

func deleteSecret(service, user string) error {
	query := itemQuery(service, user)
	defer C.CFRelease(C.CFTypeRef(query))

	return keychainError(C.SecItemDelete(C.CFDictionaryRef(query)))
}

func itemQuery(service, user string) C.CFMutableDictionaryRef {
	query := C.CFDictionaryCreateMutable(
		C.CFAllocatorRef(0),
		0,
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks,
	)
	C.CFDictionarySetValue(
		query,
		unsafe.Pointer(C.kSecClass),
		unsafe.Pointer(C.kSecClassGenericPassword),
	)

	serviceString := cfString(service)
	defer C.CFRelease(C.CFTypeRef(serviceString))
	C.CFDictionarySetValue(
		query,
		unsafe.Pointer(C.kSecAttrService),
		unsafe.Pointer(serviceString),
	)

	userString := cfString(user)
	defer C.CFRelease(C.CFTypeRef(userString))
	C.CFDictionarySetValue(
		query,
		unsafe.Pointer(C.kSecAttrAccount),
		unsafe.Pointer(userString),
	)

	return query
}

func trustedApplicationAccess(descriptor string) (C.SecAccessRef, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("resolve executable path: %w", err)
	}
	if resolvedPath, err := filepath.EvalSymlinks(executablePath); err == nil {
		executablePath = resolvedPath
	}

	cPath := C.CString(executablePath)
	defer C.free(unsafe.Pointer(cPath))

	descriptorString := cfString(descriptor)
	defer C.CFRelease(C.CFTypeRef(descriptorString))

	var access C.SecAccessRef
	status := C.create_access_for_path(cPath, descriptorString, &access)
	if err := keychainError(status); err != nil {
		return 0, err
	}

	return access, nil
}

func createGenericPasswordItem(service, user, secret string, access C.SecAccessRef) C.OSStatus {
	serviceBytes := []byte(service)
	userBytes := []byte(user)
	labelBytes := []byte(service)
	secretBytes := []byte(secret)

	var servicePtr, userPtr, labelPtr, secretPtr unsafe.Pointer
	if len(serviceBytes) > 0 {
		servicePtr = C.CBytes(serviceBytes)
		defer C.free(servicePtr)
	}
	if len(userBytes) > 0 {
		userPtr = C.CBytes(userBytes)
		defer C.free(userPtr)
	}
	if len(labelBytes) > 0 {
		labelPtr = C.CBytes(labelBytes)
		defer C.free(labelPtr)
	}
	if len(secretBytes) > 0 {
		secretPtr = C.CBytes(secretBytes)
		defer C.free(secretPtr)
	}

	var item C.SecKeychainItemRef
	status := C.create_generic_password_item(
		(*C.char)(servicePtr), C.UInt32(len(serviceBytes)),
		(*C.char)(userPtr), C.UInt32(len(userBytes)),
		(*C.char)(labelPtr), C.UInt32(len(labelBytes)),
		secretPtr, C.UInt32(len(secretBytes)),
		access,
		&item,
	)
	if item != 0 {
		C.CFRelease(C.CFTypeRef(item))
	}
	return status
}

func cfString(s string) C.CFStringRef {
	bytes := []byte(s)
	if len(bytes) == 0 {
		return C.CFStringCreateWithBytes(C.CFAllocatorRef(0), nil, 0, C.kCFStringEncodingUTF8, 0)
	}
	return C.CFStringCreateWithBytes(
		C.CFAllocatorRef(0),
		(*C.UInt8)(unsafe.Pointer(&bytes[0])),
		C.CFIndex(len(bytes)),
		C.kCFStringEncodingUTF8,
		0,
	)
}

func data(s string) C.CFDataRef {
	bytes := []byte(s)
	if len(bytes) == 0 {
		return C.CFDataCreate(C.CFAllocatorRef(0), nil, 0)
	}
	return C.CFDataCreate(
		C.CFAllocatorRef(0),
		(*C.UInt8)(unsafe.Pointer(&bytes[0])),
		C.CFIndex(len(bytes)),
	)
}

func bytes(data C.CFDataRef) string {
	length := C.CFDataGetLength(data)
	if length == 0 {
		return ""
	}
	ptr := C.CFDataGetBytePtr(data)
	return string(C.GoBytes(unsafe.Pointer(ptr), C.int(length)))
}

func keychainError(status C.OSStatus) error {
	switch status {
	case C.errSecSuccess:
		return nil
	case C.OSStatus(errSecItemNotFound):
		return ErrNotFound
	default:
		return fmt.Errorf("keychain error: %d", int(status))
	}
}

func decode(secret string) (string, error) {
	if strings.HasPrefix(secret, encodingPrefix) {
		decoded, err := hex.DecodeString(secret[len(encodingPrefix):])
		return string(decoded), err
	}
	if strings.HasPrefix(secret, base64EncodingPrefix) {
		decoded, err := base64.StdEncoding.DecodeString(secret[len(base64EncodingPrefix):])
		return string(decoded), err
	}
	return secret, nil
}
