package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
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
  mbr                enable MBR shadowing on when the device is powered down
  erase-lr           erase the named locking range
  secure-erase-lr    erase (securely) the named locking range
  psid-revert-tpr    revert TPR with PSID
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
	if err := run(flag.Arg(0), flag.Args()[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(-1)
	}
}

func run(name string, argv []string) error {
	var cmd *command
	switch name {
	case "scan":
		cmd = mkcmd(name, "", cmdScan)
	case "hash":
		cmd = mkcmd(name, "DEVICE", cmdHash)
		addPasswordFlags(cmd)
	case "save":
		cmd = mkSessionCmd(name, "DEVICE <RW|RO|LK>", cmdSave)
	case "lock-unlock":
		cmd = mkSessionCmd(name, "DEVICE <RW|RO|LK>", cmdLockUnlock)
	case "take-ownership":
		cmd = mkKeyCmd(name, "DEVICE", cmdTakeOwnership)
	case "activate-lsp":
		cmd = mkKeyCmd(name, "DEVICE", cmdActivateLSP)
	case "set-password":
		cmd = mkSessionCmd(name, "DEVICE", cmdSetPassword)
	case "activate-user":
		cmd = mkKeyCmd(name, "DEVICE USER", cmdActivateUser)
	case "revert-tpr":
		cmd = mkKeyCmd(name, "DEVICE", cmdRevertTPR)
	case "setup-lr":
		cmd = mkSessionCmd(name, "DEVICE", cmdSetupLR)
		cmd.fs.BoolVar(&wleFlag, "wle", true, "write lock enabled")
		cmd.fs.BoolVar(&rleFlag, "rle", true, "read lock enabled")
	case "add-user-to-lr":
		cmd = mkKeyCmd(name, "DEVICE USER <RW|RO|LK>", cmdAddUserToLR)
	case "mbr":
		cmd = mkKeyCmd(name, "DEVICE <yes|no>", cmdMBR)
	case "erase-lr":
		cmd = mkSessionCmd(name, "DEVICE", cmdEraseLR)
	case "secure-erase-lr":
		cmd = mkSessionCmd(name, "DEVICE", cmdSecureEraseLR)
	case "psid-revert-tpr":
		cmd = mkKeyCmd(name, "DEVICE", cmdPSIDRevertTPR)
	case "mbr-done":
		cmd = mkKeyCmd(name, "DEVICE <yes|no>", cmdMBRDone)
	case "mbr-write-shadow":
		cmd = mkKeyCmd(name, "DEVICE <yes|no>", cmdMBRWriteShadow)
	default:
		flag.Usage()
		os.Exit(2)
	}

	if err := cmd.fs.Parse(argv); err != nil {
		return err
	}
	if cmd.na != cmd.fs.NArg() {
		cmd.fs.Usage()
		os.Exit(2)
	}
	if err := cmd.fn(cmd.fs.Args()); err != nil {
		if err == errUsage {
			cmd.fs.Usage()
			os.Exit(2)
		}
		return err
	}
	return nil
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

func cmdHash(argv []string) error {
	passwd, err := getPassword(argv[0])
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(passwd))
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

func cmdTakeOwnership(client *opal.Client, key *opal.Key, argv []string) error {
	return client.TakeOwnership(key)
}

func cmdActivateLSP(client *opal.Client, key *opal.Key, argv []string) error {
	return client.ActivateLSP(key)
}

var (
	newUser     opal.User
	newPassword []byte
)

func cmdSetPassword(client *opal.Client, sess *opal.Session, argv []string) error {
	key, err := opal.NewKey(newPassword, 0)
	if err != nil {
		return err
	}
	newUsr, err := opal.NewSession(key, newUser, false)
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

func cmdPSIDRevertTPR(client *opal.Client, key *opal.Key, argv []string) error {
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
	return client.MBRWriteShadow(key, os.Stdin)
}

func parseLockingState(s string) (opal.LockUnlockState, error) {
	switch s {
	case "RW":
		return opal.LockUnlockReadWrite, nil
	case "RO":
		return opal.LockUnlockReadOnly, nil
	case "LK":
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
	switch s {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	default:
		return false, fmt.Errorf("cannot parse %q as yes/no choice", s)
	}
}

var (
	pwdFileFlag string
	sha512Flag  bool
)

func addPasswordFlags(cmd *command) {
	cmd.fs.BoolVar(&sha512Flag, "sha512", false, "use PBKDF2-HMAC-SHA512")
	cmd.fs.StringVar(&pwdFileFlag, "pwdfile", "", "`path` to file with password")
}

func withKey(
	fn func(client *opal.Client, key *opal.Key, argv []string) error,
) func([]string) error {
	return func(argv []string) error {
		passwd, err := getPassword(argv[0])
		if err != nil {
			return err
		}
		key, err := opal.NewKey(passwd, lrFlag)
		if err != nil {
			return err
		}
		client, err := opal.Open(argv[0])
		if err != nil {
			return err
		}
		defer client.Close()
		return fn(client, key, argv[1:])
	}
}

func withSession(
	fn func(client *opal.Client, sess *opal.Session, argv []string) error,
) func([]string) error {
	return withKey(func(client *opal.Client, key *opal.Key, argv []string) error {
		sess, err := opal.NewSession(key, userFlag, sumFlag)
		if err != nil {
			return err
		}
		return fn(client, sess, argv)
	})
}

func mkKeyCmd(
	name, usage string,
	fn func(client *opal.Client, key *opal.Key, argv []string) error,
) *command {
	cmd := mkcmd(name, usage, withKey(fn))
	cmd.fs.UintVar(&lrFlag, "lr", 0, "locking range `number` (default GlobalLR)")
	addPasswordFlags(cmd)
	return cmd
}

var (
	userFlag opal.User
	lrFlag   uint
	sumFlag  bool
)

func mkSessionCmd(
	name, usage string,
	fn func(client *opal.Client, sess *opal.Session, argv []string) error,
) *command {
	cmd := mkcmd(name, usage, withSession(fn))
	cmd.fs.Var((*userVar)(&userFlag), "user", "set `username` (default Admin1)")
	cmd.fs.UintVar(&lrFlag, "lr", 0, "locking range `number` (default GlobalLR)")
	cmd.fs.BoolVar(&sumFlag, "sum", false, "enable the Single User Mode")
	addPasswordFlags(cmd)
	return cmd
}

func mkcmd(name, usage string, fn func([]string) error) *command {
	var na int
	if usage != "" {
		na = strings.Count(usage, " ") + 1
	}

	cmd := &command{
		fs: flag.NewFlagSet(name, flag.ExitOnError),
		fn: fn,
		na: na,
	}
	cmd.fs.Usage = func() {
		var hasFlags bool
		cmd.fs.VisitAll(func(f *flag.Flag) {
			hasFlags = true
		})
		fmt.Fprintf(os.Stderr, `Usage: opalctl %s [option...] %s`,
			name, usage)
		fmt.Fprint(os.Stderr, "\n")
		if hasFlags {
			fmt.Fprint(os.Stderr, "\nOptions:\n")
			cmd.fs.PrintDefaults()
		}
	}
	return cmd
}

type command struct {
	fs *flag.FlagSet
	fn func([]string) error
	na int
}

func getPassword(device string) ([]byte, error) {
	var b []byte
	var err error

	env := os.Getenv("OPAL_PASSWORD")
	switch {
	case pwdFileFlag != "":
		b, err = ioutil.ReadFile(pwdFileFlag)
	case env != "":
		b = []byte(env)
	case terminal.Isatty():
		s := fmt.Sprintf("[opal] enter %s password for %s: ", userFlag, device)
		b, err = terminal.Prompt(s)
	default:
		b, err = ioutil.ReadAll(os.Stdin)
	}
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("password is empty")
	}

	// TODO: if rawFlag {
	// TODO: 	if isHex {
	// TODO: 		return hex.DecodeString(string(b))
	// TODO: 	}
	// TODO: 	return b, nil
	// TODO: }
	return hash.Hash(b, device,
		hash.WithSHA512(sha512Flag),
		// TODO: hash.WithSalt(saltFlag),
	)
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
