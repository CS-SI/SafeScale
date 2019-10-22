// +build !windows

package concurrency

import (
	"golang.org/x/sys/unix"
)

func goid() int {
	return unix.Gettid()
}
