package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/amenzhinsky/opal"
	"github.com/amenzhinsky/opal/hash"
	"github.com/amenzhinsky/opal/terminal"
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
  scan
  hash
  save
  lock-unlock
  take-ownership
  activate-lsp
  set-password
  activate-user
  retert-tpr
  lr-setup
  add-user-to-lr
  mbr
  erase-lr
  secure-erase-lr
  psid-revert-tpr
  mbr-done
  mbr-write-shadow

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
		os.Exit(-1)
	}
}

func run(fs *flag.FlagSet, argv []string) error {
	switch fs.Name() {
	case "scan":
		return cmdScan(fs, argv)
	case "hash":
		return cmdHash(fs, argv)
	case "save":
		return cmdSave(fs, argv)
	case "lkul":
		return cmdLockUnlock(fs, argv)
	case "mbr":
		return cmdMbr(fs, argv)
	default:
		return errUnknownCmd
	}
}

func cmdScan(fs *flag.FlagSet, argv []string) error {
	fs.Usage = mkUsage(fs, "")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	root := "/sys/class/block"
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if _, err = os.Stat(filepath.Join(path, "device")); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		fmt.Println(info.Name())
		return nil
	})
}

func cmdHash(fs *flag.FlagSet, argv []string) error {
	var (
		sha512Flag bool
		iterFlag   int
		lenFlag    int
		saltFlag   string
	)
	fs.Usage = mkUsage(fs, "DEVICE")
	fs.BoolVar(&sha512Flag, "sha512", false, "use PBKDF2-HMAC-SHA512")
	fs.IntVar(&iterFlag, "iter", 0, "`number` of iterations")
	fs.IntVar(&lenFlag, "len", 0, "key length in `bytes`")
	fs.StringVar(&saltFlag, "salt", "", "hashing `salt`")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errUsage
	}

	passwd, err := getPassword(opal.Admin1, fs.Arg(0), false, false)
	if err != nil {
		return err
	}
	b, err := hash.Hash(passwd, fs.Arg(0),
		hash.WithIterations(iterFlag),
		hash.WithKeyLength(lenFlag),
		hash.WithSHA512(sha512Flag),
		hash.WithSalt([]byte(saltFlag)),
	)
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(b))
	return nil
}

func cmdSave(fs *flag.FlagSet, argv []string) error {
	fs.Usage = mkUsage(fs, "DEVICE")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errUsage
	}

	passwd, err := getPassword(opal.Admin1, fs.Arg(0), false, false)
	if err != nil {
		return err
	}
	_ = passwd

	return nil
}

func cmdLockUnlock(fs *flag.FlagSet, argv []string) error {
	var (
		userFlag = opal.Admin1
		lrFlag   uint
	)
	fs.Usage = mkUsage(fs, "DEVICE <RW|RO|LK>")
	fs.UintVar(&lrFlag, "lr", 0, "locking range number")
	fs.Var((*userVar)(&userFlag), "user", "set `username` (default Admin1)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errUsage
	}

	var state opal.LockUnlockState
	switch fs.Arg(1) {
	case "RW":
		state = opal.LockUnlockReadWrite
	case "RO":
		state = opal.LockUnlockReadOnly
	case "LK":
		state = opal.LockUnlockLock
	default:
		return fmt.Errorf("unknown locking range state %q", fs.Arg(1))
	}

	passwd, err := getPassword(userFlag, fs.Arg(0), false, false)
	if err != nil {
		return err
	}

	key, err := opal.NewKey(passwd, lrFlag)
	if err != nil {
		return err
	}

	c, err := opal.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer c.Close()
	return c.LockUnlock(opal.NewSession(key, userFlag), state)
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

	passwd, err := getPassword(opal.Admin1, fs.Arg(0), false, false)
	if err != nil {
		return err
	}

	_ = enable
	_ = passwd // TODO
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

func getPassword(user opal.User, device string, isRaw, isHex bool) ([]byte, error) {
	var b []byte
	var err error
	if terminal.Isatty() {
		s := fmt.Sprintf("[opal] enter %s password for %s: ", user, device)
		b, err = terminal.Prompt(s)
	} else {
		b, err = ioutil.ReadAll(os.Stdin)
	}
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("passwd is empty")
	}

	if isRaw {
		if isHex {
			return hex.DecodeString(string(b))
		}
		return b, nil
	}
	return hash.Hash(b, device)
}

type userVar opal.User

func (f *userVar) Set(s string) error {
	switch s {
	case "Admin1":
		*f = userVar(opal.Admin1)
	case "User1":
		*f = userVar(opal.User1)
	case "User2":
		*f = userVar(opal.User2)
	case "User3":
		*f = userVar(opal.User3)
	case "User4":
		*f = userVar(opal.User4)
	case "User5":
		*f = userVar(opal.User5)
	case "User6":
		*f = userVar(opal.User6)
	case "User7":
		*f = userVar(opal.User7)
	case "User8":
		*f = userVar(opal.User8)
	case "User9":
		*f = userVar(opal.User9)
	default:
		return fmt.Errorf("unknown user %q", s)
	}
	return nil
}

func (f *userVar) String() string {
	return opal.User(*f).String()
}
