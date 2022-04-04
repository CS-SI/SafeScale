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

package ssh

import (
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v21/lib/utils"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

// Tunnel a SSH tunnel
type Tunnel struct {
	port      uint
	cmd       *exec.Cmd
	cmdString string
	keyFile   *os.File
}

type Tunnels []*Tunnel

// Close closes ssh tunnel
func (stun *Tunnel) Close() fail.Error {
	defer debug.NewTracer(nil, true).Entering().Exiting()

	defer func() {
		if lazyErr := utils.LazyRemove(stun.keyFile.Name()); lazyErr != nil {
			logrus.Error(lazyErr)
		}
	}()

	xerr := killProcess(stun.cmd.Process)
	if xerr != nil {
		return xerr
	}

	// Kills remaining processes if there are some
	bytesCmd, err := exec.Command("pgrep", "-f", stun.cmdString).Output()
	if err != nil {
		_, code, problem := utils.ExtractRetCode(err)
		if problem != nil {
			return fail.Wrap(err, "unable to close tunnel, running pgrep")
		}
		if code == 1 { // no process found
			debug.IgnoreError(err)
			return nil
		}
		if code == 127 { // pgrep not installed
			debug.IgnoreError(fmt.Errorf("pgrep not installed"))
			return nil
		}
		return fail.Wrap(err, "unable to close tunnel, unexpected errorcode running pgrep: %d", code)
	}

	portStr := strings.Trim(string(bytesCmd), "\n")
	if _, err = strconv.Atoi(portStr); err != nil {
		return fail.Wrap(err, "unable to close tunnel")
	}

	if err = exec.Command("kill", "-9", portStr).Run(); err != nil {
		return fail.Wrap(err, "unable to close tunnel: %s", fmt.Sprintf("kill -9 failed: %s", reflect.TypeOf(err).String()))
	}

	return nil
}

// Close closes all the tunnels
func (tunnels Tunnels) Close() fail.Error {
	var errorList []error
	for _, t := range tunnels {
		if xerr := t.Close(); xerr != nil {
			errorList = append(errorList, xerr)
		}
	}
	if len(errorList) > 0 {
		return fail.NewErrorList(errorList)
	}

	return nil
}
