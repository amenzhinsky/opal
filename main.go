package main

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/pbkdf2"
)

// #include "opal.h"
import "C"

var verboseFlag bool

// https://gitlab.com/zub2/opalctl/blob/master/src/opalpba.c
func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %s [common-option...] COMMAND [arg...]

Commands:
  hash
  mbr
  save
  lkul

Common options:
`, filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.BoolVar(&verboseFlag, "verbose", false, "enable verbose output")
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(); err != nil {
		if err == flag.ErrHelp {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

func run() error {
	fs, argv := flag.NewFlagSet(flag.Arg(0), flag.ContinueOnError), flag.Args()[1:]
	switch fs.Name() {
	case "hash":
		return cmdHash(fs, argv)
	case "save":
		return cmdSave(fs, argv)
	case "mbr":
		return cmdMbr(fs, argv)
	default:
		flag.Usage()
		return flag.ErrHelp
	}
}

func cmdHash(fs *flag.FlagSet, argv []string) error {
	var sha512Flag bool
	fs.Usage = mkUsage(fs, "DEVICE",
		"sedutil-cli compatible password hashing using PBKDF2-HMAC-SHA1.")
	fs.BoolVar(&sha512Flag, "sha512", false, "use PBKDF2-HMAC-SHA512")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return flag.ErrHelp
	}

	serial, err := getSerial(fs.Arg(0))
	if err != nil {
		return err
	}
	passwd, err := getPassword()
	if err != nil {
		return err
	}
	hash := sha1.New
	if sha512Flag {
		hash = sha512.New
	}
	b := pbkdf2.Key(passwd, serial, 75000, 32, hash)
	fmt.Println(hex.EncodeToString(b))
	return nil
}

func cmdSave(fs *flag.FlagSet, argv []string) error {
	var (
		hexFlag bool
		//stdinFlag bool
		fileFlag string
	)
	fs.Usage = mkUsage(fs, "DEVICE", "")
	fs.BoolVar(&hexFlag, "hex", false, "password is hex encoded")
	//fs.BoolVar(&stdinFlag, "stdin", false, "read password from stdin")
	fs.StringVar(&fileFlag, "file", "", "read password from the `filepath`")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return flag.ErrHelp
	}

	passwd, err := getPassword()
	if err != nil {
		return err
	}
	if hexFlag {
		passwd, err = hex.DecodeString(string(passwd))
		if err != nil {
			return err
		}
	}

	return opalLockUnlock(fs.Arg(0), passwd)
}

func cmdMbr(fs *flag.FlagSet, argv []string) error {
	fs.Usage = mkUsage(fs, "DEVICE on|off", "")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return flag.ErrHelp
	}

	var action C.enum_opal_mbr
	switch fs.Arg(1) {
	case "on":
		action = C.OPAL_MBR_ENABLE
	case "off":
		action = C.OPAL_MBR_DISABLE
	default:
		fs.Usage()
		return flag.ErrHelp
	}

	passwd, err := getPassword()
	if err != nil {
		return err
	}
	key, err := newKey(passwd)
	if err != nil {
		return err
	}

	fmt.Printf("--> %#v\n", &C.struct_opal_mbr_data{
		key:            *key,
		enable_disable: C.__u8(action),
	})
	return nil
}

func cmdMbrDone(fs *flag.FlagSet, argv []string) error {
	return nil
}

func opalLockUnlock(dev string, passwd []byte) error {
	f, err := os.OpenFile("/dev/"+dev, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	lkul, err := newLockUnlock(passwd)
	if err != nil {
		return err
	}
	return opalErr(C.opal_lock_unlock(C.int(f.Fd()), lkul))
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
		who:      C.OPAL_ADMIN1,
		opal_key: *key,
	}, nil
}

func newKey(key []byte) (*C.struct_opal_key, error) {
	k := &C.struct_opal_key{
		lr:      0,
		key_len: C.__u8(len(key)),
	}
	if len(k.key) < len(key) {
		return nil, errors.New("key is too long")
	}
	for i := range key {
		k.key[i] = C.__u8(key[i])
	}
	return k, nil
}

func mkUsage(fs *flag.FlagSet, usage, description string) func() {
	return func() {
		fmt.Fprintf(os.Stderr, `Usage: %s [common-option...] %s [option...] %s`,
			filepath.Base(os.Args[0]), fs.Name(), usage)
		fmt.Fprint(os.Stderr, "\n")
		if description != "" {
			fmt.Fprint(os.Stderr, "\n", description, "\n")
		}
		if fs.NFlag() > 0 {
			fmt.Fprint(os.Stderr, "\nOptions:\n")
			fs.PrintDefaults()
		}
		fmt.Fprint(os.Stderr, "\nCommon options:\n")
		flag.PrintDefaults()
	}
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

func getSerial(device string) ([]byte, error) {
	p := fmt.Sprintf("/sys/class/block/%s/device/serial", device)
	f, err := os.OpenFile(p, os.O_RDONLY, 0)
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

func getPassword() ([]byte, error) {
	// TODO: isatty
	return ioutil.ReadAll(os.Stdin)
}
