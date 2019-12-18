// +build !windows

package concurrency

import (
	"golang.org/x/sys/unix"
)

func goid() int { // nolint
	return unix.Gettid()
}
