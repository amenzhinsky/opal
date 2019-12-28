package termios

import (
	"os"
	"syscall"
	"unsafe"
)

const ECHO = 0000010

func Get() (*syscall.Termios, error) {
	var term syscall.Termios
	if err := ioctl(syscall.TCGETS, &term); err != nil {
		return nil, err
	}
	return &term, nil
}

func Set(term *syscall.Termios) error {
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
