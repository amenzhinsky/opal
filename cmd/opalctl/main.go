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
  take-ownership     take ownership and change Admin1 password from MSID 
  activate-lsp       change state of the Locking SP
  set-password       change user password
  activate-user      activate a non-admin user
  revert-tpr         reset device to the factory state
  lr-setup           set up a locking range
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

var (
	pwdFileFlag string
	sha512Flag  bool
	userFlag    opal.User
	lrFlag      uint
)

func addPasswordFlags(cmd *command) {
	cmd.fs.BoolVar(&sha512Flag, "sha512", false, "use PBKDF2-HMAC-SHA512")
	cmd.fs.StringVar(&pwdFileFlag, "pwdfile", "", "`path` to file with password")
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
		cmd = mkKeyCmd(name, "DEVICE", cmdActivateLsp)
	case "set-password":
		cmd = mkSessionCmd(name, "DEVICE", cmdSetPassword)
	case "activate-user":
		cmd = mkSessionCmd(name, "DEVICE", cmdActivateUser)
	case "revert-tpr":
		cmd = mkKeyCmd(name, "DEVICE", cmdRevertTpr)
	case "lr-setup":
		cmd = mkSessionCmd(name, "DEVICE", cmdLrSetup)
	case "add-user-to-lr":
		cmd = mkSessionCmd(name, "DEVICE <RW|RO|LK>", cmdAddUserToLr)
	case "mbr":
		cmd = mkKeyCmd(name, "DEVICE <yes|no>", cmdMbr)
	case "erase-lr":
		cmd = mkSessionCmd(name, "DEVICE", cmdEraseLr)
	case "secure-erase-lr":
		cmd = mkSessionCmd(name, "DEVICE", cmdSecureEraseLr)
	case "psid-revert-tpr":
		cmd = mkKeyCmd(name, "DEVICE", cmdPsidRevertTpr)
	case "mbr-done":
		cmd = mkKeyCmd(name, "DEVICE <yes|no>", cmdMbrDone)
	case "mbr-write-shadow":
		cmd = mkKeyCmd(name, "DEVICE <yes|no>", cmdMbrWriteShadow)
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

func cmdActivateLsp(client *opal.Client, key *opal.Key, argv []string) error {
	return client.ActivateLsp(key)
}

func cmdSetPassword(client *opal.Client, sess *opal.Session, argv []string) error {
	// TODO
	panic("TODO")
	return nil
}

func cmdActivateUser(client *opal.Client, sess *opal.Session, argv []string) error {
	return client.ActivateUsr(sess)
}

func cmdRevertTpr(client *opal.Client, key *opal.Key, argv []string) error {
	return client.RevertTpr(key)
}

func cmdLrSetup(client *opal.Client, sess *opal.Session, argv []string) error {
	return client.LrSetup(sess)
}

func cmdAddUserToLr(client *opal.Client, sess *opal.Session, argv []string) error {
	state, err := parseLockingState(argv[0])
	if err != nil {
		return err
	}
	return client.AddUserToLr(sess, state)
}

func cmdMbr(client *opal.Client, key *opal.Key, argv []string) error {
	enable, err := parseYesNo(argv[0])
	if err != nil {
		return err
	}
	return client.EnableDisableMbr(key, enable)
}

func cmdEraseLr(client *opal.Client, sess *opal.Session, argv []string) error {
	return client.EraseLr(sess)
}

func cmdSecureEraseLr(client *opal.Client, sess *opal.Session, argv []string) error {
	return client.SecureEraseLr(sess)
}

func cmdPsidRevertTpr(client *opal.Client, key *opal.Key, argv []string) error {
	// TODO: key here can be only PSID
	panic("todo")
	return client.PsidRevertTpr(key)
}

func cmdMbrDone(client *opal.Client, key *opal.Key, argv []string) error {
	done, err := parseYesNo(argv[0])
	if err != nil {
		return err
	}
	return client.MbrDone(key, done)
}

func cmdMbrWriteShadow(client *opal.Client, key *opal.Key, argv []string) error {
	// TODO
	panic("TODO")
	return client.MbrWriteShadow(key, nil)
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

func mkKeyCmd(
	name, usage string,
	fn func(client *opal.Client, key *opal.Key, argv []string) error,
) *command {
	cmd := mkcmd(name, usage, withKey(fn))
	cmd.fs.UintVar(&lrFlag, "lr", 0, "locking range `number`")
	addPasswordFlags(cmd)
	return cmd
}

func mkSessionCmd(
	name, usage string,
	fn func(client *opal.Client, sess *opal.Session, argv []string) error,
) *command {
	cmd := mkcmd(name, usage, withSession(fn))
	cmd.fs.Var((*userVar)(&userFlag), "user", "set `username` (default Admin1)")
	cmd.fs.UintVar(&lrFlag, "lr", 0, "locking range `number`") // same as in mkKeyCmd
	addPasswordFlags(cmd)
	return cmd
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
		return fn(client, opal.NewSession(key, userFlag), argv)
	})
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
		return nil, errors.New("passwd is empty")
	}

	//if rawFlag {
	//	if isHex {
	//		return hex.DecodeString(string(b))
	//	}
	//	return b, nil
	//}
	return hash.Hash(b, device,
		hash.WithSHA512(sha512Flag),
		//hash.WithSalt(saltFlag),
		//has
	)
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
