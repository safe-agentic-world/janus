//go:build windows

package main

import "os"

func reloadSignals() []os.Signal {
	return nil
}
