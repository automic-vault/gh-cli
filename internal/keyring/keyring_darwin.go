//go:build darwin

package keyring

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unsafe"
)

const (
	encodingPrefix       = "go-keyring-encoded:"
	base64EncodingPrefix = "go-keyring-base64:"
	errSecItemNotFound   = -25300
)

func set(service, user, secret string) error {
	query := itemQuery(service, user)
	defer C.CFRelease(C.CFTypeRef(query))

	secretData := data(secret)
	defer C.CFRelease(C.CFTypeRef(secretData))

	C.CFDictionarySetValue(
		query,
		unsafe.Pointer(C.kSecValueData),
		unsafe.Pointer(secretData),
	)

	status := C.SecItemAdd(C.CFDictionaryRef(query), nil)
	if status != C.errSecDuplicateItem {
		return keychainError(status)
	}
	if err := deleteSecret(service, user); err != nil {
		return err
	}
	return keychainError(C.SecItemAdd(C.CFDictionaryRef(query), nil))
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
