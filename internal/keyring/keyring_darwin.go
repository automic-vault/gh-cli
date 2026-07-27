//go:build darwin

package keyring

/*
#cgo CFLAGS: -fblocks
#include <xpc/xpc.h>
#include <stdlib.h>

void av_xpc_connection_set_event_handler(xpc_connection_t connection);

static xpc_type_t av_xpc_type_error(void) {
	return XPC_TYPE_ERROR;
}

static const char *av_xpc_error_description(xpc_object_t object) {
	return xpc_dictionary_get_string(object, XPC_ERROR_KEY_DESCRIPTION);
}

*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

const approvalService = "com.automicvault.av2.approval"
const approvalServiceSigningRequirement = `anchor apple generic and certificate leaf[subject.OU] = ZU76A67LGU and identifier "com.automicvault"`

const humanApprovalRequiredEvent = "human-approval-required"
const humanApprovalRequiredNotice = "automic vault: human approval required\n"

func approvalEventNotice(event string) string {
	if event == humanApprovalRequiredEvent {
		return humanApprovalRequiredNotice
	}
	return ""
}

func approvalDecisionNotice(decision string) string {
	switch decision {
	case "approved":
		return "automic vault: approved\n"
	case "denied":
		return "automic vault: denied\n"
	default:
		return ""
	}
}

//export av_approval_event
func av_approval_event(eventName *C.char) {
	if notice := approvalEventNotice(C.GoString(eventName)); notice != "" {
		_, _ = io.WriteString(os.Stderr, notice)
	}
}

func set(service, user, secret string) error {
	key := vaultKey(service, user)
	message := C.xpc_dictionary_create_empty()
	if unsafe.Pointer(message) == nil {
		return errors.New("failed to create Automic Vault XPC message")
	}
	defer C.xpc_release(message)

	if err := setString(message, "op", "gh-save"); err != nil {
		return err
	}
	if err := setString(message, "key", key); err != nil {
		return err
	}
	if err := setString(message, "value", secret); err != nil {
		return err
	}
	reply, err := send(message)
	if err != nil {
		return err
	}
	defer C.xpc_release(reply)
	return replyError(reply, "secret save failed")
}

func get(service, user string) (string, error) {
	key := vaultKey(service, user)
	message := C.xpc_dictionary_create_empty()
	if unsafe.Pointer(message) == nil {
		return "", errors.New("failed to create Automic Vault XPC message")
	}
	defer C.xpc_release(message)

	if err := setString(message, "op", "keys"); err != nil {
		return "", err
	}
	if err := addRequestMetadata(message, service, user, key); err != nil {
		return "", err
	}
	reply, err := send(message)
	if err != nil {
		return "", err
	}
	defer C.xpc_release(reply)
	if err := replyError(reply, "key request denied"); err != nil {
		return "", err
	}

	secretsKey := C.CString("secrets")
	defer C.free(unsafe.Pointer(secretsKey))
	secrets := C.xpc_dictionary_get_value(reply, secretsKey)
	if unsafe.Pointer(secrets) == nil {
		return "", ErrNotFound
	}
	keyCString := C.CString(key)
	defer C.free(unsafe.Pointer(keyCString))
	value := C.xpc_dictionary_get_string(secrets, keyCString)
	if value == nil {
		return "", ErrNotFound
	}
	return C.GoString(value), nil
}

func deleteSecret(service, user string) error {
	key := vaultKey(service, user)
	message := C.xpc_dictionary_create_empty()
	if unsafe.Pointer(message) == nil {
		return errors.New("failed to create Automic Vault XPC message")
	}
	defer C.xpc_release(message)

	if err := setString(message, "op", "gh-delete"); err != nil {
		return err
	}
	if err := setString(message, "key", key); err != nil {
		return err
	}
	reply, err := send(message)
	if err != nil {
		return err
	}
	defer C.xpc_release(reply)
	return replyError(reply, "secret delete failed")
}

func addRequestMetadata(message C.xpc_object_t, service, user, key string) error {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	target, err := os.Executable()
	if err != nil {
		target = "gh"
	} else if resolved, err := filepath.EvalSymlinks(target); err == nil {
		target = resolved
	}
	args := make([]string, 0, len(os.Args)-1)
	if len(os.Args) > 1 {
		args = append(args, os.Args[1:]...)
	}

	for k, v := range map[string]string{
		"target": target,
		"cwd":    cwd,
		"tool":   "gh",
		"title":  "GitHub token requested",
		"detail": tokenRequestDetail(service, user),
	} {
		if err := setString(message, k, v); err != nil {
			return err
		}
	}
	replaceKey := C.CString("replace_existing_env")
	defer C.free(unsafe.Pointer(replaceKey))
	C.xpc_dictionary_set_bool(message, replaceKey, true)
	allowMissingKey := C.CString("allow_missing_keys")
	defer C.free(unsafe.Pointer(allowMissingKey))
	C.xpc_dictionary_set_bool(message, allowMissingKey, false)
	if err := setArray(message, "keys", []string{key}); err != nil {
		return err
	}
	if err := setArray(message, "args", args); err != nil {
		return err
	}
	return setArray(message, "env_conflicts", nil)
}

func send(message C.xpc_object_t) (C.xpc_object_t, error) {
	service := C.CString(approvalService)
	defer C.free(unsafe.Pointer(service))
	connection := C.xpc_connection_create_mach_service(service, nil, 0)
	if unsafe.Pointer(connection) == nil {
		return nil, errors.New("failed to create Automic Vault XPC connection")
	}
	defer C.xpc_release(C.xpc_object_t(unsafe.Pointer(connection)))
	defer C.xpc_connection_cancel(connection)

	requirement := C.CString(approvalServiceSigningRequirement)
	defer C.free(unsafe.Pointer(requirement))
	if C.xpc_connection_set_peer_code_signing_requirement(connection, requirement) != 0 {
		return nil, errors.New("failed to configure Automic Vault XPC signing requirement")
	}

	C.av_xpc_connection_set_event_handler(connection)
	C.xpc_connection_activate(connection)

	reply := C.xpc_connection_send_message_with_reply_sync(connection, message)
	if unsafe.Pointer(reply) == nil {
		return nil, errors.New("Automic Vault approval did not reply")
	}
	if C.xpc_get_type(reply) == C.av_xpc_type_error() {
		desc := C.av_xpc_error_description(reply)
		err := "Automic Vault XPC connection failed"
		if desc != nil {
			err = C.GoString(desc)
		}
		C.xpc_release(reply)
		if err == "Connection invalid" {
			return nil, errors.New("Automic Vault approval service is not running; open the menu bar app")
		}
		return nil, errors.New(err)
	}
	decisionKey := C.CString("human_approval_decision")
	defer C.free(unsafe.Pointer(decisionKey))
	if decision := C.xpc_dictionary_get_string(reply, decisionKey); decision != nil {
		_, _ = io.WriteString(os.Stderr, approvalDecisionNotice(C.GoString(decision)))
	}
	return reply, nil
}

func replyError(reply C.xpc_object_t, fallback string) error {
	okKey := C.CString("ok")
	defer C.free(unsafe.Pointer(okKey))
	if C.xpc_dictionary_get_bool(reply, okKey) {
		return nil
	}
	errorKey := C.CString("error")
	defer C.free(unsafe.Pointer(errorKey))
	err := C.xpc_dictionary_get_string(reply, errorKey)
	if err == nil {
		return errors.New(fallback)
	}
	message := C.GoString(err)
	if message == "not found" || strings.Contains(message, "-25300") {
		return ErrNotFound
	}
	return errors.New(message)
}

func setString(dict C.xpc_object_t, key, value string) error {
	keyCString := C.CString(key)
	defer C.free(unsafe.Pointer(keyCString))
	valueCString, err := cStringValue(value)
	if err != nil {
		return err
	}
	defer C.free(unsafe.Pointer(valueCString))
	C.xpc_dictionary_set_string(dict, keyCString, valueCString)
	return nil
}

func setArray(dict C.xpc_object_t, key string, values []string) error {
	keyCString := C.CString(key)
	defer C.free(unsafe.Pointer(keyCString))
	array := C.xpc_array_create_empty()
	if unsafe.Pointer(array) == nil {
		return errors.New("failed to create Automic Vault XPC array")
	}
	defer C.xpc_release(array)
	for _, value := range values {
		valueCString, err := cStringValue(value)
		if err != nil {
			return err
		}
		item := C.xpc_string_create(valueCString)
		C.free(unsafe.Pointer(valueCString))
		if unsafe.Pointer(item) == nil {
			return errors.New("failed to create Automic Vault XPC string")
		}
		C.xpc_array_append_value(array, item)
		C.xpc_release(item)
	}
	C.xpc_dictionary_set_value(dict, keyCString, array)
	return nil
}

func cStringValue(value string) (*C.char, error) {
	if strings.IndexByte(value, 0) >= 0 {
		return nil, fmt.Errorf("XPC field contains NUL: %q", value)
	}
	return C.CString(value), nil
}

func tokenRequestDetail(service, user string) string {
	host := strings.TrimPrefix(service, "gh:")
	if user == "" {
		return fmt.Sprintf("gh needs the active GitHub token for %s", host)
	}
	return fmt.Sprintf("gh needs the GitHub token for %s account %s", host, user)
}

func vaultKey(service, user string) string {
	parts := []string{"GH_TOKEN", sanitizeKeyPart(strings.TrimPrefix(service, "gh:"))}
	if user != "" {
		parts = append(parts, sanitizeKeyPart(user))
	}
	return strings.Join(parts, "_")
}

func sanitizeKeyPart(value string) string {
	var b strings.Builder
	lastUnderscore := false
	for _, r := range strings.ToUpper(value) {
		ok := r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if ok {
			b.WriteRune(r)
			lastUnderscore = false
		} else if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}
