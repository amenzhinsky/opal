package hash

import (
	"crypto/sha1"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

// Option is a Hash configuration option.
type Option func(s *settings)

// WithIterations sets the iterations count.
func WithIterations(iter int) Option {
	return func(s *settings) {
		if s.iter != 0 {
			s.iter = iter
		}
	}
}

// WithKeyLength sets the generated key length in bytes.
func WithKeyLength(length int) Option {
	return func(s *settings) {
		if length != 0 {
			s.keyLen = length
		}
	}
}

// WithSHA512 uses SHA512 hashing function instead of the default SHA1.
func WithSHA512(enabled bool) Option {
	return func(s *settings) {
		if enabled {
			s.h = sha512.New
		}
	}
}

type settings struct {
	iter   int
	keyLen int
	h      func() hash.Hash
}

// Hash is a compatibility layer with sedutil.
//
// Instead of sending a raw password to hardware it hashes it
// with pbkdf2 using device's serial as a salt.
//
// The original sedutil uses SHA1 hashing whereas some forks
// already switched to SHA512 in order to enhance security.
func Hash(passwd []byte, device string, opts ...Option) ([]byte, error) {
	serial, err := getSerial(device)
	if err != nil {
		return nil, err
	}
	s := &settings{
		iter:   75000,
		keyLen: 32,
		h:      sha1.New,
	}
	for _, opt := range opts {
		opt(s)
	}
	return pbkdf2.Key(passwd, serial, s.iter, s.keyLen, s.h), nil
}

func getSerial(device string) ([]byte, error) {
	p := fmt.Sprintf("/sys/class/block/%s/device/serial", device)
	f, err := os.OpenFile(p, os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, 20)
	n, err := f.Read(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, errors.New("invalid serial length")
	}
	return b, nil
}
