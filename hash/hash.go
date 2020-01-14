package hash

import (
	"crypto/sha1"
	"crypto/sha512"
	"fmt"
	"hash"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

// #include "block.h"
import "C"

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

func WithSalt(salt []byte) Option {
	return func(s *settings) {
		s.salt = salt
	}
}

type settings struct {
	iter   int
	keyLen int
	salt   []byte
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
	// TODO: open once in the main package
	f, err := os.OpenFile("/dev/"+device, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := &settings{
		iter:   75000,
		keyLen: 32,
		h:      sha1.New,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.salt == nil {
		s.salt, err = getSerial(f)
		if err != nil {
			return nil, err
		}
	}
	return pbkdf2.Key(passwd, s.salt, s.iter, s.keyLen, s.h), nil
}

func getSerial(f *os.File) ([]byte, error) {
	var serial [20]C.uchar
	ret, errno := C.get_serial(C.int(f.Fd()), &serial[0])
	if ret != 0 {
		if ret == -1 {
			return nil, errno
		}
		return nil, fmt.Errorf("get_serial = %d code", int(ret))
	}
	b := make([]byte, len(serial))
	for i := range serial {
		b[i] = byte(serial[i])
	}
	return b, nil
}
