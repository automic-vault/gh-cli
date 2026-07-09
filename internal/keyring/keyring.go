// Package keyring is a simple wrapper that adds timeouts to the zalando/go-keyring package.
package keyring

import (
	"errors"
	"time"

	"github.com/zalando/go-keyring"
)

var ErrNotFound = errors.New("secret not found in keyring")
var mockProvider bool

const keyringTimeout = 5 * time.Minute

type TimeoutError struct {
	message string
}

func (e *TimeoutError) Error() string {
	return e.message
}

// Set secret in keyring for user.
func Set(service, user, secret string) error {
	ch := make(chan error, 1)
	go func() {
		defer close(ch)
		if mockProvider {
			ch <- keyring.Set(service, user, secret)
			return
		}
		ch <- set(service, user, secret)
	}()
	select {
	case err := <-ch:
		return err
<<<<<<< HEAD
	case <-time.After(keyringTimeout):
		return &TimeoutError{"timeout while trying to set secret in keyring"}
	}
}

// Get secret from keyring given service and user name.
func Get(service, user string) (string, error) {
	ch := make(chan struct {
		val string
		err error
	}, 1)
	go func() {
		defer close(ch)
		var val string
		var err error
		if mockProvider {
			val, err = keyring.Get(service, user)
		} else {
			val, err = get(service, user)
		}
		ch <- struct {
			val string
			err error
		}{val, err}
	}()
	select {
	case res := <-ch:
		if errors.Is(res.err, keyring.ErrNotFound) {
			return "", ErrNotFound
		}
		return res.val, res.err
<<<<<<< HEAD
	case <-time.After(keyringTimeout):
		return "", &TimeoutError{"timeout while trying to get secret from keyring"}
	}
}

// Delete secret from keyring.
func Delete(service, user string) error {
	ch := make(chan error, 1)
	go func() {
		defer close(ch)
		if mockProvider {
			ch <- keyring.Delete(service, user)
			return
		}
		ch <- deleteSecret(service, user)
	}()
	select {
	case err := <-ch:
		return err
<<<<<<< HEAD
	case <-time.After(keyringTimeout):
		return &TimeoutError{"timeout while trying to delete secret from keyring"}
	}
}

func MockInit() {
	mockProvider = true
	keyring.MockInit()
}

func MockInitWithError(err error) {
	mockProvider = true
	keyring.MockInitWithError(err)
}
