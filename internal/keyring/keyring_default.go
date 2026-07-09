//go:build !darwin

package keyring

import "github.com/zalando/go-keyring"

func set(service, user, secret string) error {
	return keyring.Set(service, user, secret)
}

func get(service, user string) (string, error) {
	return keyring.Get(service, user)
}

func deleteSecret(service, user string) error {
	return keyring.Delete(service, user)
}
