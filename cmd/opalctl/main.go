package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/amenzhinsky/opal"
	"github.com/amenzhinsky/opal/hash"
	"github.com/amenzhinsky/opal/terminal"
)

var debugFlag bool

var errUsage = errors.New("invalid usage")

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: opalctl [option...] COMMAND

Commands:
  scan               detect all block devices and show OPAL statuses
  hash               hash user password with sedutil compatible algorithm
  save               register a lock-unlock command after S3 sleep
  lock-unlock        lock or onlock a locking range
  take-ownership     change the SecurityID and Admin1 passwords from MSID 
  activate-lsp       change state of the LockingSP
  set-password       change the password in the LockingSP
  activate-user      activate a non-admin user
  revert-tpr         reset device to the factory state
  setup-lr           set up a locking range
  add-user-to-lr     add a user to a locking range
  erase-lr           erase the named locking range
  secure-erase-lr    erase (securely) the named locking range
  psid-revert-tpr    revert TPR with PSID
  mbr-enable         enable MBR shadowing on when the device is powered down
  mbr-done           swith the drive out of the shadowed state
  mbr-write-shadow   write MBR shadow table

Options:
`)
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Run 'opalctl COMMAND -h' for more information on a command")
	}
	flag.BoolVar(&debugFlag, "debug", false, "enable debug mode")
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	cmd := lookup(flag.Arg(0))
	if cmd == nil {
		flag.Usage()
		os.Exit(2)
	}
	if err := cmd(flag.Args()[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

func lookup(name string) func(argv []string) error {
	switch name {
	case "scan":
		return mkCmd(name, "", cmdScan)
	case "hash":
		return mkCmd(name, "<dev>", cmdHash, func(fs *flag.FlagSet) {
			fs.BoolVar(&sha512Flag, "sha512", false, "use PBKDF2-HMAC-SHA512")
		})
	case "save":
		return mkUsrCmd(name, "<dev> rw|ro|lk", cmdSave, addSUMFlag, addLRFlag)
	case "lock-unlock":
		return mkUsrCmd(name, "<dev> rw|ro|lk", cmdLockUnlock, addSUMFlag, addLRFlag)
	case "take-ownership":
		return mkAdmCmd(name, "<dev>", cmdTakeOwnership)
	case "activate-lsp":
		return mkAdmCmd(name, "<dev>", cmdActivateLSP)
		// TODO: addSUMFlag
		// TODO: addLRFlag
	case "set-password":
		return mkUsrCmd(name, "<dev> <usr>", cmdSetPassword, addSUMFlag)
	case "activate-user":
		return mkAdmCmd(name, "<dev> <usr>", cmdActivateUser)
	case "revert-tpr":
		return mkAdmCmd(name, "<dev>", cmdRevertTPR)
	case "setup-lr":
		return mkUsrCmd(name, "<dev>", cmdSetupLR, addSUMFlag, addLRFlag,
			func(fs *flag.FlagSet) {
				fs.BoolVar(&wleFlag, "wle", true, "write lock enabled")
				fs.BoolVar(&rleFlag, "rle", true, "read lock enabled")
			},
		)
	case "add-user-to-lr":
		return mkAdmCmd(name, "<dev> <usr> rw|ro|lk", cmdAddUserToLR, addLRFlag)
	case "erase-lr":
		return mkUsrCmd(name, "<dev>", cmdEraseLR, addSUMFlag, addLRFlag)
	case "secure-erase-lr":
		return mkUsrCmd(name, "<dev>", cmdSecureEraseLR, addSUMFlag, addLRFlag)
	case "psid-revert-tpr":
		return mkCliCmd(name, "<dev> <psid>", cmdPSIDRevertTPR)
	case "mbr-enable":
		return mkAdmCmd(name, "<dev> y|n", cmdMBR)
	case "mbr-done":
		return mkAdmCmd(name, "<dev> y|n", cmdMBRDone)
	case "mbr-write-shadow":
		return mkAdmCmd(name, "<dev> <pba>", cmdMBRWriteShadow)
	default:
		return nil
	}
}

func cmdScan(argv []string) error {
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

var sha512Flag bool

func cmdHash(argv []string) error {
	passwd, err := prompt("enter password to hash: ")
	if err != nil {
		return err
	}
	b, err := hash.Hash(passwd, argv[0],
		hash.WithSHA512(sha512Flag),
	)
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(b))
	return nil
}

func cmdSave(client *opal.Client, sess *opal.Session, argv []string) error {
	state, err := parseLockingState(argv[0])
	if err != nil {
		return err
	}
	return client.Save(sess, state)
}

func cmdLockUnlock(client *opal.Client, sess *opal.Session, argv []string) error {
	state, err := parseLockingState(argv[0])
	if err != nil {
		return err
	}
	return client.LockUnlock(sess, state)
}

func cmdTakeOwnership(client *opal.Client, key *opal.Key, _ []string) error {
	return client.TakeOwnership(key)
}

func cmdActivateLSP(client *opal.Client, key *opal.Key, _ []string) error {
	return client.ActivateLSP(key)
}

func cmdSetPassword(client *opal.Client, sess *opal.Session, argv []string) error {
	user, err := parseUser(argv[0])
	if err != nil {
		return err
	}
	// TODO: accept hex passwords
	p1, err := prompt("enter new %s password: ", user)
	if err != nil {
		return err
	}
	p2, err := prompt("retype new %s password: ", user)
	if err != nil {
		return err
	}
	if !bytes.Equal(p1, p2) {
		return errors.New("passwords don't match")
	}
	key, err := opal.NewKey(p1, 0)
	if err != nil {
		return err
	}
	newUsr, err := opal.NewSession(key, user, false)
	if err != nil {
		return err
	}
	return client.SetPassword(sess, newUsr)
}

func cmdActivateUser(client *opal.Client, key *opal.Key, argv []string) error {
	user, err := parseUser(argv[0])
	if err != nil {
		return err
	}
	sess, err := opal.NewSession(key, user, false)
	if err != nil {
		return err
	}
	return client.ActivateUser(sess)
}

func cmdRevertTPR(client *opal.Client, key *opal.Key, argv []string) error {
	return client.RevertTPR(key)
}

var (
	rleFlag bool
	wleFlag bool
)

func cmdSetupLR(client *opal.Client, sess *opal.Session, argv []string) error {
	return client.SetupLR(sess, rleFlag, wleFlag)
}

func cmdAddUserToLR(client *opal.Client, key *opal.Key, argv []string) error {
	user, err := parseUser(argv[0])
	if err != nil {
		return err
	}
	state, err := parseLockingState(argv[1])
	if err != nil {
		return err
	}
	sess, err := opal.NewSession(key, user, false)
	if err != nil {
		return err
	}
	return client.AddUserToLR(sess, state)
}

func cmdMBR(client *opal.Client, key *opal.Key, argv []string) error {
	enable, err := parseYesNo(argv[0])
	if err != nil {
		return err
	}
	return client.EnableDisableMBR(key, enable)
}

func cmdEraseLR(client *opal.Client, sess *opal.Session, argv []string) error {
	return client.EraseLR(sess)
}

func cmdSecureEraseLR(client *opal.Client, sess *opal.Session, argv []string) error {
	return client.SecureEraseLR(sess)
}

func cmdPSIDRevertTPR(client *opal.Client, argv []string) error {
	psid, err := hex.DecodeString(argv[0])
	if err != nil {
		return fmt.Errorf("cannot parse PSID: %s", err)
	}
	key, err := opal.NewKey(psid, 0)
	if err != nil {
		return err
	}
	return client.PSIDRevertTPR(key)
}

func cmdMBRDone(client *opal.Client, key *opal.Key, argv []string) error {
	done, err := parseYesNo(argv[0])
	if err != nil {
		return err
	}
	return client.MBRDone(key, done)
}

func cmdMBRWriteShadow(client *opal.Client, key *opal.Key, argv []string) error {
	f, err := os.OpenFile(argv[0], os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return client.MBRWriteShadow(key, f)
}

func parseLockingState(s string) (opal.LockUnlockState, error) {
	switch s {
	case "rw":
		return opal.LockUnlockReadWrite, nil
	case "ro":
		return opal.LockUnlockReadOnly, nil
	case "lk":
		return opal.LockUnlockLock, nil
	default:
		return 0, fmt.Errorf("unknown locking range state %q", s)
	}
}

func parseUser(s string) (opal.User, error) {
	switch s {
	case "Admin1":
		return opal.Admin1, nil
	case "User1":
		return opal.User1, nil
	case "User2":
		return opal.User2, nil
	case "User3":
		return opal.User3, nil
	case "User4":
		return opal.User4, nil
	case "User5":
		return opal.User5, nil
	case "User6":
		return opal.User6, nil
	case "User7":
		return opal.User7, nil
	case "User8":
		return opal.User8, nil
	case "User9":
		return opal.User9, nil
	default:
		return 0, fmt.Errorf("unknown user %q", s)
	}
}

func parseYesNo(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return false, fmt.Errorf("cannot parse %q as a yes/no choice", s)
	}
}

var hexFlag bool

func addPasswordFlags(fs *flag.FlagSet) {
	fs.BoolVar(&hexFlag, "hex", false, "password is in hex form")
}

var lrFlag uint

func addLRFlag(fs *flag.FlagSet) {
	fs.UintVar(&lrFlag, "lr", 0, "locking range `number`")
}

var sumFlag bool

func addSUMFlag(fs *flag.FlagSet) {
	fs.BoolVar(&sumFlag, "sum", false, "enable the Single User Mode")
}

func mkCliCmd(
	name, usage string,
	fn func(client *opal.Client, argv []string) error,
	flags ...func(fs *flag.FlagSet),
) func(argv []string) error {
	return mkCmd(name, usage, func(argv []string) error {
		client, err := opal.Open(argv[0])
		if err != nil {
			return err
		}
		defer client.Close()
		return fn(client, argv[1:])
	}, flags...)
}

func mkAdmCmd(
	name, usage string,
	fn func(client *opal.Client, key *opal.Key, argv []string) error,
	flags ...func(fs *flag.FlagSet),
) func(argv []string) error {
	return mkCliCmd(name, usage, func(client *opal.Client, argv []string) error {
		passwd, err := getPassword(client.Device())
		if err != nil {
			return err
		}
		key, err := opal.NewKey(passwd, lrFlag)
		if err != nil {
			return err
		}
		return fn(client, key, argv)
	}, append(flags, addPasswordFlags)...)
}

var userFlag opal.User

func mkUsrCmd(
	name, usage string,
	fn func(client *opal.Client, sess *opal.Session, argv []string) error,
	flags ...func(fs *flag.FlagSet),
) func(argv []string) error {
	return mkAdmCmd(name, usage, func(client *opal.Client, key *opal.Key, argv []string) error {
		sess, err := opal.NewSession(key, userFlag, sumFlag)
		if err != nil {
			return err
		}
		return fn(client, sess, argv)
	}, append(flags,
		func(fs *flag.FlagSet) {
			fs.Var((*userVar)(&userFlag), "user", "authenticate as `username` (default Admin1)")
		},
	)...)
}

func mkCmd(
	name, usage string,
	fn func([]string) error,
	flags ...func(fs *flag.FlagSet),
) func(argv []string) error {
	var na int
	if usage != "" {
		na = strings.Count(usage, " ") + 1
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		var hasFlags bool
		fs.VisitAll(func(f *flag.Flag) {
			hasFlags = true
		})
		fmt.Fprintf(os.Stderr, `Usage: opalctl %s [option...] %s`,
			name, usage)
		fmt.Fprint(os.Stderr, "\n")
		if hasFlags {
			fmt.Fprint(os.Stderr, "\nOptions:\n")
			fs.PrintDefaults()
		}
	}
	for i := range flags {
		flags[i](fs)
	}
	return func(argv []string) error {
		if err := fs.Parse(argv); err != nil {
			return err
		}
		if na != fs.NArg() {
			fs.Usage()
			os.Exit(2)
		}
		if err := fn(fs.Args()); err != nil {
			if err == errUsage {
				fs.Usage()
				os.Exit(2)
			}
			return err
		}
		return nil
	}
}

func getPassword(device string) ([]byte, error) {
	// TODO: if s := os.Getenv("OPAL_PASSWORD"); s != "" {
	// TODO: 	return []byte(s), nil
	// TODO: }

	b, err := prompt("enter %s password for %s: ", userFlag, device)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("password is empty")
	}
	if hexFlag {
		return hex.DecodeString(string(b))
	}
	return b, nil
}

func prompt(format string, v ...interface{}) ([]byte, error) {
	return terminal.Prompt("[opal] " + fmt.Sprintf(format, v...))
}

type userVar opal.User

func (f *userVar) Set(s string) error {
	user, err := parseUser(s)
	if err != nil {
		return err
	}
	*f = userVar(user)
	return nil
}

func (f *userVar) String() string {
	return opal.User(*f).String()
}
