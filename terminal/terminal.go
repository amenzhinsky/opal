package terminal

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const echo = 0000010

func Isatty() bool {
	_, err := get()
	return err == nil
}

func Prompt(s string) ([]byte, error) {
	term, err := get()
	if err != nil {
		return nil, err
	}
	lflag := term.Lflag
	term.Lflag ^= echo
	if err = set(term); err != nil {
		return nil, err
	}
	fmt.Fprint(os.Stderr, s)
	line, _, err := bufio.NewReader(os.Stdin).ReadLine()
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr)
	term.Lflag = lflag
	if err = set(term); err != nil {
		return nil, err
	}
	return line, nil
}

func get() (*syscall.Termios, error) {
	var term syscall.Termios
	if err := ioctl(syscall.TCGETS, &term); err != nil {
		return nil, err
	}
	return &term, nil
}

func set(term *syscall.Termios) error {
	return ioctl(syscall.TCSETS, term)
}

func ioctl(op uintptr, term *syscall.Termios) error {
	if _, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		os.Stdin.Fd(),
		op,
		uintptr(unsafe.Pointer(term)),
	); errno != 0 {
		return errno
	}
	return nil
}
