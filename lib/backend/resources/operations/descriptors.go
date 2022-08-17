//go:build !windows
// +build !windows

package operations

import "golang.org/x/sys/unix"

// NOTFOUND Not found
const NOTFOUND = unix.ENOENT
