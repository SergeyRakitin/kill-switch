package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var getFinalPathNameByHandle = syscall.NewLazyDLL("kernel32.dll").NewProc("GetFinalPathNameByHandleW")

func canonicalPath(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	size := 512
	for {
		buffer := make([]uint16, size)
		n, _, callErr := getFinalPathNameByHandle.Call(file.Fd(), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0)
		if n == 0 {
			if callErr != nil && callErr != syscall.Errno(0) {
				return "", fmt.Errorf("GetFinalPathNameByHandleW: %w", callErr)
			}
			return "", errors.New("GetFinalPathNameByHandleW failed")
		}
		if n < uintptr(len(buffer)) {
			return strings.TrimPrefix(syscall.UTF16ToString(buffer), `\\?\`), nil
		}
		if n > 32768 {
			return "", errors.New("canonical path is too long")
		}
		size = int(n) + 1
	}
}
