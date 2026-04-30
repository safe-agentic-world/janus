//go:build !windows

package approval

import "os"

func replaceFile(tmp, path string) error {
	return os.Rename(tmp, path)
}

func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
