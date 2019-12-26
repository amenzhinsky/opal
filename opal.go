package opal

import (
	"errors"
	"os"
)

// #include "opal.h"
import "C"

func Save(f *os.File, passwd []byte) error {
	lkul, err := newLockUnlock(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_save(C.int(f.Fd()), lkul))
}

func LockUnlock(f *os.File, passwd []byte) error {
	lkul, err := newLockUnlock(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_lock_unlock(C.int(f.Fd()), lkul))
}

func newLockUnlock(passwd []byte) (*C.struct_opal_lock_unlock, error) {
	si, err := newSessionInfo(passwd)
	if err != nil {
		return nil, err
	}
	return &C.struct_opal_lock_unlock{
		l_state: C.OPAL_RW, // TODO: configure
		session: *si,
	}, nil
}

func TakeOwnership(f *os.File, passwd []byte) error {
	key, err := newKey(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_take_ownership(C.int(f.Fd()), key))
}

func ActivateLsp(f *os.File, passwd []byte) error {
	key, err := newKey(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_activate_lsp(C.int(f.Fd()), &C.struct_opal_lr_act{
		key: *key,
		sum: 0,
		// TODO: num_lrs: 0,
		// TODO: lr:
	}))
}

func SetPw(f *os.File, passwd []byte) error {
	si, err := newSessionInfo(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_set_pw(C.int(f.Fd()), &C.struct_opal_new_pw{
		session: *si,
		// new_user_pw: C._struct_opal_session_info{},
	}))
}

func ActivateUsr(f *os.File, passwd []byte) error {
	si, err := newSessionInfo(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_activate_usr(C.int(f.Fd()), si))
}

func RevertTpr(f *os.File, passwd []byte) error {
	key, err := newKey(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_revert_tpr(C.int(f.Fd()), key))
}

func LrSetup(f *os.File, passwd []byte) error {
	si, err := newSessionInfo(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_lr_setup(C.int(f.Fd()), &C.struct_opal_user_lr_setup{
		range_start:  0,
		range_length: 0,
		RLE:          0,
		WLE:          0,
		session:      *si,
	}))
}

func AddUserToLr(f *os.File, passwd []byte) error {
	lkul, err := newLockUnlock(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_add_usr_to_lr(C.int(f.Fd()), lkul))
}

func EnableDisableMbr(f *os.File, passwd []byte, enable bool) error {
	key, err := newKey(passwd)
	if err != nil {
		return err
	}
	enableDisable := C.OPAL_MBR_DISABLE
	if enable {
		enableDisable = C.OPAL_MBR_DISABLE
	}
	return checkErr(C.opal_enable_disable_mbr(C.int(f.Fd()), &C.struct_opal_mbr_data{
		key:            *key,
		enable_disable: C.__u8(enableDisable),
	}))
}

func EraseLr(f *os.File, passwd []byte) error {
	si, err := newSessionInfo(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_erase_lr(C.int(f.Fd()), si))
}

func SecureEraseLr(f *os.File, passwd []byte) error {
	si, err := newSessionInfo(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_secure_erase_lr(C.int(f.Fd()), si))
}

func PsidRevertTpr(f *os.File, passwd []byte) error {
	key, err := newKey(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_psid_revert_tpr(C.int(f.Fd()), key))
}

func MbrDone(f *os.File, passwd []byte, done bool) error {
	key, err := newKey(passwd)
	if err != nil {
		return err
	}
	doneFlag := C.OPAL_MBR_NOT_DONE
	if done {
		doneFlag = C.OPAL_MBR_DONE
	}
	return checkErr(C.opal_mbr_done(C.int(f.Fd()), &C.struct_opal_mbr_done{
		key:       *key,
		done_flag: C.__u8(doneFlag),
	}))
}

func MbrWriteShadow(f *os.File, passwd, data []byte) error {
	key, err := newKey(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.mbr_write_data(C.int(f.Fd()), &C.struct_opal_shadow_mbr{
		key: *key,
		//data: 0,
		//offset: 0,
		//size: 0,
	}))
}

func newSessionInfo(passwd []byte) (*C.struct_opal_session_info, error) {
	key, err := newKey(passwd)
	if err != nil {
		return nil, err
	}
	return &C.struct_opal_session_info{
		sum:      0,
		who:      C.OPAL_ADMIN1, // TODO: configure
		opal_key: *key,
	}, nil
}

func newKey(passwd []byte) (*C.struct_opal_key, error) {
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

func checkErr(ret C.int) error {
	if ret == 0 {
		return nil
	}
	return Error{ret: ret}
}

type Error struct {
	ret C.int
}

func (e Error) Error() string {
	return C.GoString(C.opal_error_to_human(e.ret))
}
