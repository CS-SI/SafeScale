/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"syscall"
)

func convertErrorToTunnelError(inErr error) (err error) {
	if inErr == nil {
		return inErr
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

	if isErrorAddressAlreadyInUse(inErr) {
		return tunnelError{
			error:       inErr,
			isTimeout:   false,
			isTemporary: true,
		}
	}

	return inErr
}

func isHandshakeError(err error) bool {
	if err == nil {
		return false
	}

	if reflect.ValueOf(err).Kind() == reflect.ValueOf(fmt.Errorf("")).Kind() { // if it's just a string we are forced to check the content
		return strings.Contains(err.Error(), "handshake")
	}

	return false
}

func isIOTimeout(err error) bool {
	if err == nil {
		return false
	}

	if reflect.ValueOf(err).Kind() == reflect.ValueOf(fmt.Errorf("")).Kind() { // if it's just a string we are forced to check the content
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

	if reflect.ValueOf(err).Kind() == reflect.ValueOf(fmt.Errorf("")).Kind() { // if it's just a string we are forced to check the content
		return strings.Contains(err.Error(), "address already in use")
	}

	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	errSyscallError, ok := errOpError.Err.(*os.SyscallError)
	if !ok {
		return false
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
