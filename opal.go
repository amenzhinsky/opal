// IOCTLs implementation can be found here:
// https://github.com/torvalds/linux/blob/master/block/sed-opal.c
package opal

import (
	"errors"
	"os"
	"syscall"
)

/*
#include <errno.h>
#include "opal.h"

extern int errno;

const __u32 opal_key_max = OPAL_KEY_MAX;
const __u32 opal_max_lrs = OPAL_MAX_LRS;

int get_errno() {
	return errno;
}
*/
import "C"

func NewKey(passwd []byte, lr uint) (*Key, error) {
	if len(passwd) > int(C.opal_key_max) {
		return nil, errors.New("opal: passwd is too long")
	}
	if lr > uint(C.opal_max_lrs) {
		return nil, errors.New("opal: lr is too big")
	}

	key := &Key{
		k: C.struct_opal_key{
			lr:      C.__u8(lr),
			key_len: C.__u8(len(passwd)),
		},
	}
	for i := range passwd {
		key.k.key[i] = C.__u8(passwd[i])
	}
	return key, nil
}

type Key struct {
	k C.struct_opal_key
}

type User uint

func (u User) String() string {
	switch u {
	case Admin1:
		return "Admin1"
	case User1:
		return "User1"
	case User2:
		return "User2"
	case User3:
		return "User3"
	case User4:
		return "User4"
	case User5:
		return "User5"
	case User6:
		return "User6"
	case User7:
		return "User7"
	case User8:
		return "User8"
	case User9:
		return "User9"
	default:
		return "Unknown"
	}
}

const (
	Admin1 User = C.OPAL_ADMIN1
	User1  User = C.OPAL_USER1
	User2  User = C.OPAL_USER2
	User3  User = C.OPAL_USER3
	User4  User = C.OPAL_USER4
	User5  User = C.OPAL_USER5
	User6  User = C.OPAL_USER6
	User7  User = C.OPAL_USER7
	User8  User = C.OPAL_USER8
	User9  User = C.OPAL_USER9
)

func NewSession(key *Key, user User) *Session {
	return &Session{s: C.struct_opal_session_info{
		// TODO: sum:      0,
		who:      C.__u32(user),
		opal_key: key.k,
	}}
}

type Session struct {
	s C.struct_opal_session_info
}

func Open(device string) (*Client, error) {
	f, err := os.OpenFile("/dev/"+device, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	return &Client{f: f}, nil
}

type Client struct {
	f *os.File
}

func (c *Client) Save(sess *Session, state LockUnlockState) error {
	lkul, err := newLockUnlock(sess, state)
	if err != nil {
		return err
	}
	return checkErr(C.opal_save(c.fd(), lkul))
}

func (c *Client) LockUnlock(sess *Session, state LockUnlockState) error {
	lkul, err := newLockUnlock(sess, state)
	if err != nil {
		return err
	}
	return checkErr(C.opal_lock_unlock(c.fd(), lkul))
}

func (c *Client) TakeOwnership(key *Key) error {
	return checkErr(C.opal_take_ownership(c.fd(), &key.k))
}

func (c *Client) ActivateLsp(key *Key) error {
	return checkErr(C.opal_activate_lsp(c.fd(), &C.struct_opal_lr_act{
		key: key.k,
		// TODO: sum: 0,
		// TODO: num_lrs: 0,
		// TODO: lr:
	}))
}

func (c *Client) SetPw(sess *Session) error {
	return checkErr(C.opal_set_pw(c.fd(), &C.struct_opal_new_pw{
		session: sess.s,
		// TODO: new_user_pw: C.struct_opal_session_info{},
	}))
}

func (c *Client) ActivateUsr(sess *Session) error {
	return checkErr(C.opal_activate_usr(c.fd(), &sess.s))
}

func (c *Client) RevertTpr(key *Key) error {
	return checkErr(C.opal_revert_tpr(c.fd(), &key.k))
}

func (c *Client) LrSetup(sess *Session) error {
	return checkErr(C.opal_lr_setup(c.fd(), &C.struct_opal_user_lr_setup{
		// TODO: range_start:  0,
		// TODO: range_length: 0,
		// TODO: RLE:          0,
		// TODO: WLE:          0,
		session: sess.s,
	}))
}

func (c *Client) AddUserToLr(sess *Session, state LockUnlockState) error {
	lkul, err := newLockUnlock(sess, state)
	if err != nil {
		return err
	}
	return checkErr(C.opal_add_usr_to_lr(c.fd(), lkul))
}

func (c *Client) EnableDisableMbr(key *Key, enable bool) error {
	enableDisable := C.OPAL_MBR_DISABLE
	if enable {
		enableDisable = C.OPAL_MBR_DISABLE
	}
	return checkErr(C.opal_enable_disable_mbr(c.fd(), &C.struct_opal_mbr_data{
		key:            key.k,
		enable_disable: C.__u8(enableDisable),
	}))
}

func (c *Client) EraseLr(sess *Session) error {
	return checkErr(C.opal_erase_lr(c.fd(), &sess.s))
}

func (c *Client) SecureEraseLr(sess *Session) error {
	return checkErr(C.opal_secure_erase_lr(c.fd(), &sess.s))
}

func (c *Client) PsidRevertTpr(key *Key) error {
	return checkErr(C.opal_psid_revert_tpr(c.fd(), &key.k))
}

func (c *Client) MbrDone(key *Key, done bool) error {
	doneFlag := C.OPAL_MBR_NOT_DONE
	if done {
		doneFlag = C.OPAL_MBR_DONE
	}
	return checkErr(C.opal_mbr_done(c.fd(), &C.struct_opal_mbr_done{
		key:       key.k,
		done_flag: C.__u8(doneFlag),
	}))
}

func (c *Client) MbrWriteShadow(key *Key, data []byte) error {
	return checkErr(C.opal_write_shadow_mbr(c.fd(), &C.struct_opal_shadow_mbr{
		key: key.k,
		// TODO: data: 0,
		// TODO: offset: 0,
		// TODO: size: 0,
	}))
}

func (c *Client) Close() error {
	return c.f.Close()
}

func (c *Client) fd() C.int {
	return C.int(c.f.Fd())
}

type LockUnlockState uint

const (
	LockUnlockReadOnly  LockUnlockState = C.OPAL_RO
	LockUnlockReadWrite LockUnlockState = C.OPAL_RW
	LockUnlockLock      LockUnlockState = C.OPAL_LK
)

func newLockUnlock(sess *Session, state LockUnlockState) (*C.struct_opal_lock_unlock, error) {
	return &C.struct_opal_lock_unlock{
		l_state: C.__u32(state),
		session: sess.s,
	}, nil
}

func checkErr(ret C.int) error {
	if ret == 0 {
		return nil
	}
	if ret == -1 {
		return syscall.Errno(C.get_errno())
	}
	return Error{ret: ret}
}

type Error struct {
	ret C.int
}

func (e Error) Error() string {
	return C.GoString(C.opal_error_to_human(e.ret))
}
