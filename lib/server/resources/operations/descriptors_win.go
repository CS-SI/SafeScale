//go:build windows
// +build windows

package operations

import "syscall"

// NOTFOUND Not found
const NOTFOUND = syscall.Errno(0x2)
