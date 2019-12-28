package opal

import (
	"errors"
	"os"
)

// #include "opal.h"
import "C"

func New(device string) (*Client, error) {
	f, err := os.OpenFile("/dev/"+device, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	return &Client{f: f}, nil
}

type Client struct {
	f *os.File
}

func (c *Client) Save(passwd []byte) error {
	lkul, err := newLockUnlock(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_save(c.fd(), lkul))
}

func (c *Client) LockUnlock(passwd []byte) error {
	lkul, err := newLockUnlock(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_lock_unlock(c.fd(), lkul))
}

func (c *Client) TakeOwnership(passwd []byte) error {
	key, err := newKey(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_take_ownership(c.fd(), key))
}

func (c *Client) ActivateLsp(passwd []byte) error {
	key, err := newKey(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_activate_lsp(c.fd(), &C.struct_opal_lr_act{
		key: *key,
		sum: 0,
		// TODO: num_lrs: 0,
		// TODO: lr:
	}))
}

func (c *Client) SetPw(passwd []byte) error {
	si, err := newSessionInfo(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_set_pw(c.fd(), &C.struct_opal_new_pw{
		session: *si,
		// new_user_pw: C._struct_opal_session_info{},
	}))
}

func (c *Client) ActivateUsr(passwd []byte) error {
	si, err := newSessionInfo(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_activate_usr(c.fd(), si))
}

func (c *Client) RevertTpr(passwd []byte) error {
	key, err := newKey(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_revert_tpr(c.fd(), key))
}

func (c *Client) LrSetup(passwd []byte) error {
	si, err := newSessionInfo(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_lr_setup(c.fd(), &C.struct_opal_user_lr_setup{
		range_start:  0,
		range_length: 0,
		RLE:          0,
		WLE:          0,
		session:      *si,
	}))
}

func (c *Client) AddUserToLr(passwd []byte) error {
	lkul, err := newLockUnlock(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_add_usr_to_lr(c.fd(), lkul))
}

func (c *Client) EnableDisableMbr(passwd []byte, enable bool) error {
	key, err := newKey(passwd)
	if err != nil {
		return err
	}
	enableDisable := C.OPAL_MBR_DISABLE
	if enable {
		enableDisable = C.OPAL_MBR_DISABLE
	}
	return checkErr(C.opal_enable_disable_mbr(c.fd(), &C.struct_opal_mbr_data{
		key:            *key,
		enable_disable: C.__u8(enableDisable),
	}))
}

func (c *Client) EraseLr(passwd []byte) error {
	si, err := newSessionInfo(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_erase_lr(c.fd(), si))
}

func (c *Client) SecureEraseLr(passwd []byte) error {
	si, err := newSessionInfo(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_secure_erase_lr(c.fd(), si))
}

func (c *Client) PsidRevertTpr(passwd []byte) error {
	key, err := newKey(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_psid_revert_tpr(c.fd(), key))
}

func (c *Client) MbrDone(passwd []byte, done bool) error {
	key, err := newKey(passwd)
	if err != nil {
		return err
	}
	doneFlag := C.OPAL_MBR_NOT_DONE
	if done {
		doneFlag = C.OPAL_MBR_DONE
	}
	return checkErr(C.opal_mbr_done(c.fd(), &C.struct_opal_mbr_done{
		key:       *key,
		done_flag: C.__u8(doneFlag),
	}))
}

func (c *Client) MbrWriteShadow(passwd, data []byte) error {
	key, err := newKey(passwd)
	if err != nil {
		return err
	}
	return checkErr(C.opal_write_shadow_mbr(c.fd(), &C.struct_opal_shadow_mbr{
		key: *key,
		//data: 0,
		//offset: 0,
		//size: 0,
	}))
}

func (c *Client) Close() error {
	return c.f.Close()
}

func (c *Client) fd() C.int {
	return C.int(c.f.Fd())
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
