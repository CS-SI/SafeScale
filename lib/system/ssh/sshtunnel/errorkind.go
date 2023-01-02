/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sshtunnel

import (
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
)

func lastUnwrap(in error) (err error) {
	if in == nil {
		return nil
	}

	last := in
	for {
		err = last
		u, ok := last.(interface {
			Unwrap() error
		})
		if !ok {
			break
		}
		last = u.Unwrap()
	}

	return err
}

func convertErrorToTunnelError(inErr error) (err error) {
	if inErr == nil {
		return nil
	}

	if _, ok := inErr.(tunnelError); ok {
		return inErr
	}

	if isIOTimeout(inErr) {
		return tunnelError{
			error:       inErr,
			isTimeout:   true,
			isTemporary: true,
		}
	}

	if isHandshakeError(inErr) {
		return tunnelError{
			error:       inErr,
			isTimeout:   false,
			isTemporary: true,
		}
	}

	if isConnectionResetByPeer(inErr) {
		return tunnelError{
			error:       nil,
			isTimeout:   false,
			isTemporary: true,
		}
	}

	if isErrorAddressAlreadyInUse(inErr) {
		return tunnelError{
			error:       inErr,
			isTimeout:   false,
			isTemporary: true,
		}
	}

	if isConnectionRefused(inErr) || isConnectionRefusedError(inErr) {
		return tunnelError{
			error:       inErr,
			isTimeout:   false,
			isTemporary: true,
		}
	}

	if isNativeSSHLibError(inErr) {
		return tunnelError{
			error:       inErr,
			isTimeout:   false,
			isTemporary: false,
		}
	}

	if isHostNotFoundError(inErr) {
		return tunnelError{
			error:       inErr,
			isTimeout:   false,
			isTemporary: false,
		}
	}

	if _, ok := inErr.(*net.OpError); ok {
		return tunnelError{
			error:       inErr,
			isTimeout:   false,
			isTemporary: false,
		}
	}

	return inErr
}

func isHostNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	err = lastUnwrap(err)

	if !isNativeSSHLibError(err) {
		return false
	}

	var sshErr *ssh.OpenChannelError
	if ok := errors.As(err, &sshErr); ok {
		if sshErr.Reason != 2 {
			return false
		}

		if strings.Contains(sshErr.Message, "route") {
			return true
		}
	}

	return false
}

func isConnectionRefusedError(err error) bool {
	if err == nil {
		return false
	}

	err = lastUnwrap(err)

	if !isNativeSSHLibError(err) {
		return false
	}

	var sshErr *ssh.OpenChannelError
	if ok := errors.As(err, &sshErr); ok {
		if sshErr.Reason != 2 {
			return false
		}

		if strings.Contains(sshErr.Message, "refused") {
			return true
		}
	}

	return false
}

func isNativeSSHLibError(err error) bool {
	if err == nil {
		return false
	}

	err = lastUnwrap(err)

	if _, ok := err.(*ssh.OpenChannelError); ok {
		return true
	}

	if _, ok := err.(*ssh.PassphraseMissingError); ok {
		return true
	}

	if _, ok := err.(*ssh.ServerAuthError); ok {
		return true
	}

	if _, ok := err.(*ssh.ExitMissingError); ok {
		return true
	}

	if _, ok := err.(*ssh.ExitError); ok {
		return true
	}

	return false
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}

	err = lastUnwrap(err)

	if netOp, ok := err.(*net.OpError); ok {
		if strings.Contains(netOp.Err.Error(), "refused") {
			return true
		}

		if netOp.Op == "dial" {
			if netSysCall, ok := netOp.Err.(*os.SyscallError); ok {
				if netSysCall.Syscall == "connectex" {
					return true
				}
			}
		}
	}

	if sysc, ok := err.(syscall.Errno); ok {
		if sysc == syscall.ECONNREFUSED {
			return true
		}
	}

	return false
}

func isHandshakeError(err error) bool {
	if err == nil {
		return false
	}

	err = lastUnwrap(err)

	if reflect.ValueOf(err).Kind() == reflect.ValueOf("").Kind() { // if it's just a string we are forced to check the content
		return strings.Contains(err.Error(), "handshake failed")
	}

	return false
}

func isConnectionResetByPeer(err error) bool {
	if err == nil {
		return false
	}

	err = lastUnwrap(err)

	if !isHandshakeError(err) {
		return false
	}

	if reflect.ValueOf(err).Kind() == reflect.ValueOf("").Kind() { // if it's just a string we are forced to check the content
		return strings.Contains(err.Error(), "connection reset by peer")
	}

	return false
}

func isIOTimeout(err error) bool {
	if err == nil {
		return false
	}

	err = lastUnwrap(err)

	if reflect.ValueOf(err).Kind() == reflect.ValueOf("").Kind() { // if it's just a string we are forced to check the content
		return strings.Contains(err.Error(), "i/o timeout")
	}

	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}

	return errOpError.Timeout()
}

func isErrorAddressAlreadyInUse(err error) bool {
	if err == nil {
		return false
	}

	err = lastUnwrap(err)

	if reflect.ValueOf(err).Kind() == reflect.ValueOf("").Kind() { // if it's just a string we are forced to check the content
		return strings.Contains(err.Error(), "address already in use")
	}

	var errOpError *net.OpError
	ok := errors.As(err, &errOpError)
	if !ok {
		return false
	}
	errSyscallError, ok := errOpError.Err.(*os.SyscallError)
	if !ok {
		return false
	}

	if errOpError.Op == "listen" {
		if errSyscallError.Syscall == "bind" {
			return true
		}
	}

	errErrno, ok := errSyscallError.Err.(syscall.Errno)
	if !ok {
		return false
	}
	if errErrno == syscall.EADDRINUSE {
		return true
	}

	return false
}
