//go:build windows
// +build windows

package resources

import "syscall"

// NOTFOUND Not found
const NOTFOUND = syscall.Errno(0x2)
