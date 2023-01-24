//go:build !windows
// +build !windows

package resources

import "golang.org/x/sys/unix"

// NOTFOUND Not found
const NOTFOUND = unix.ENOENT
