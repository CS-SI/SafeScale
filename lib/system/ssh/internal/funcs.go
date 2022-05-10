//go:build !tunnel
// +build !tunnel

/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package internal

import (
	"os"
	"syscall"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sirupsen/logrus"
)

// KillProcess sends a kill signal to the process passed as parameter and Wait() for it to release resources (and prevent zombie...)
func KillProcess(proc *os.Process) fail.Error {
	err := proc.Kill()
	if err != nil {
		switch cerr := err.(type) {
		case syscall.Errno:
			switch cerr {
			case syscall.ESRCH:
				// process not found, continue
				debug.IgnoreError(err)
			default:
				logrus.Errorf("proc.Kill() failed: %s", cerr.Error())
				return fail.Wrap(err, "unable to send kill signal to process")
			}
		default:
			switch err.Error() {
			case "os: process already finished":
				debug.IgnoreError(err)
			default:
				logrus.Errorf("proc.Kill() failed: %s", err.Error())
				return fail.Wrap(err, "unable to send kill signal to process")
			}
		}
	}

	_, err = proc.Wait()
	if err != nil {
		switch cerr := err.(type) {
		case *os.SyscallError:
			err = cerr.Err
		default:
		}
		switch err {
		case syscall.ESRCH, syscall.ECHILD:
			// process not found or has no child, continue
			debug.IgnoreError(err)
		default:
			logrus.Error(err.Error())
			return fail.Wrap(err, "unable to wait on SSH tunnel process")
		}
	}

	return nil
}
