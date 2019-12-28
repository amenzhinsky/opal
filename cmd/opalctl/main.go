package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	_ "github.com/amenzhinsky/opal"
	"github.com/amenzhinsky/opal/termios"
	"golang.org/x/crypto/pbkdf2"
)

var verboseFlag bool

var (
	errUsage      = errors.New("invalid usage")
	errUnknownCmd = errors.New("unknown command")
)

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

	fs := flag.NewFlagSet(flag.Arg(0), flag.ExitOnError)
	if err := run(fs, flag.Args()[1:]); err != nil {
		if err == errUnknownCmd {
			flag.Usage()
			os.Exit(2)
		}
		if err == errUsage {
			fs.Usage()
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(255)
	}
}

func run(fs *flag.FlagSet, argv []string) error {
	switch fs.Name() {
	case "hash":
		return cmdHash(fs, argv)
	case "save":
		return cmdSave(fs, argv)
	case "mbr":
		return cmdMbr(fs, argv)
	default:
		return errUnknownCmd
	}
}

func cmdHash(fs *flag.FlagSet, argv []string) error {
	var (
		sha512Flag bool
		iterFlag   int
		lenFlag    int
	)
	fs.Usage = mkUsage(fs, "DEVICE")
	fs.BoolVar(&sha512Flag, "sha512", false, "use PBKDF2-HMAC-SHA512")
	fs.IntVar(&iterFlag, "iter", 75000, "`number` of iterations")
	fs.IntVar(&lenFlag, "len", 32, "key length in `bytes`")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errUsage
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

	b := pbkdf2.Key(passwd, serial, iterFlag, lenFlag, hash)
	fmt.Println(hex.EncodeToString(b))
	return nil
}

func cmdSave(fs *flag.FlagSet, argv []string) error {
	var (
		hexFlag bool
		//stdinFlag bool
		fileFlag string
	)
	fs.Usage = mkUsage(fs, "DEVICE")
	fs.BoolVar(&hexFlag, "hex", false, "password is hex encoded")
	//fs.BoolVar(&stdinFlag, "stdin", false, "read password from stdin")
	fs.StringVar(&fileFlag, "file", "", "read password from the `filepath`")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errUsage
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

	return nil
	//return opal.LockUnlock(f, passwd)
}

func cmdMbr(fs *flag.FlagSet, argv []string) error {
	fs.Usage = mkUsage(fs, "DEVICE on|off")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errUsage
	}

	var enable bool
	switch fs.Arg(1) {
	case "on":
		enable = true
	case "off":
		enable = false
	default:
		return errUsage
	}

	passwd, err := getPassword()
	if err != nil {
		return err
	}

	_ = enable
	_ = passwd // TODO
	return nil
}

func cmdMbrDone(fs *flag.FlagSet, argv []string) error {
	return nil
}

func mkUsage(fs *flag.FlagSet, usage string) func() {
	return func() {
		var hasFlags bool
		fs.VisitAll(func(f *flag.Flag) {
			hasFlags = true
		})

		fmt.Fprintf(os.Stderr, `Usage: %s [common-option...] %s [option...] %s`,
			filepath.Base(os.Args[0]), fs.Name(), usage)
		fmt.Fprint(os.Stderr, "\n")
		if hasFlags {
			fmt.Fprint(os.Stderr, "\nOptions:\n")
			fs.PrintDefaults()
		}
		fmt.Fprint(os.Stderr, "\nCommon options:\n")
		flag.PrintDefaults()
	}
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
	term, err := termios.Get()
	if err != nil {
		// not a tty, read until EOF
		return ioutil.ReadAll(os.Stdin)
	}
	term.Lflag ^= termios.ECHO
	if err = termios.Set(term); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "Enter password: ")
	line, _, err := bufio.NewReader(os.Stdin).ReadLine()
	if err != nil {
		return nil, err
	}
	return line, nil
}
