package opal

import (
	"errors"
	"os"
)

// #include "opal.h"
import "C"

func LockUnlock(dev string, passwd []byte) error {
	f, err := os.OpenFile("/dev/"+dev, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	lkul, err := NewLockUnlock(passwd)
	if err != nil {
		return err
	}
	return opalErr(C.opal_lock_unlock(C.int(f.Fd()), lkul))
}

func NewLockUnlock(passwd []byte) (*C.struct_opal_lock_unlock, error) {
	si, err := NewSessionInfo(passwd)
	if err != nil {
		return nil, err
	}
	return &C.struct_opal_lock_unlock{
		l_state: C.OPAL_RW, // TODO: configure
		session: *si,
	}, nil
}

func NewSessionInfo(passwd []byte) (*C.struct_opal_session_info, error) {
	key, err := NewKey(passwd)
	if err != nil {
		return nil, err
	}
	return &C.struct_opal_session_info{
		sum:      0,
		who:      C.OPAL_ADMIN1, // TODO: configure
		opal_key: *key,
	}, nil
}

func NewKey(passwd []byte) (*C.struct_opal_key, error) {
	key := &C.struct_opal_key{
		lr:      0,
		key_len: C.__u8(len(passwd)),
	}
	if len(key.key) < len(passwd) {
		return nil, errors.New("passwd is too long")
	}
	for i := range passwd {
		key.key[i] = C.__u8(passwd[i])
	}
	return key, nil
}

func NewMBRData(enable bool, passwd []byte) (*C.struct_opal_mbr_data, error) {
	key, err := NewKey(passwd)
	if err != nil {
		return nil, err
	}
	enableDisable := C.OPAL_MBR_DISABLE
	if enable {
		enableDisable = C.OPAL_MBR_DISABLE
	}
	return &C.struct_opal_mbr_data{
		key:            *key,
		enable_disable: C.__u8(enableDisable),
	}, nil
}

func opalErr(ret C.int) error {
	if ret == 0 {
		return nil
	}
	return opalError{ret: ret}
}

type opalError struct {
	ret C.int
}

func (e opalError) Error() string {
	return C.GoString(C.opal_error_to_human(e.ret))
}
