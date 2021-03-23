// +build !windows,!darwin,ignore

package concurrency

import (
	"golang.org/x/sys/unix"
)

func goid() int { // nolint
	return unix.Gettid()
}
