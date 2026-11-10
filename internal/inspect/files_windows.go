package inspect

import (
	"os"

	"golang.org/x/sys/windows"
)

func openRead(root *os.Root, name string) (*os.File, error) {
	// Root confines resolution; openRegular also verifies the opened identity.
	return root.Open(name)
}

func IsTerminal(f *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}
