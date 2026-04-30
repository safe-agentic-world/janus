//go:build windows

package approval

import (
	"syscall"
	"unsafe"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

func replaceFile(tmp, path string) error {
	tmpPtr, err := syscall.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")
	ret, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(tmpPtr)),
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(moveFileReplaceExisting|moveFileWriteThrough),
	)
	if ret == 0 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return syscall.EINVAL
	}
	return nil
}

func syncDir(_ string) error {
	return nil
}
