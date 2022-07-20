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

package sshtunnel

import (
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

func RunCommandInSSHSessionWithTimeout(se *ssh.Session, cmd string, timeout time.Duration) (err error) {
	defer OnPanic(&err)

	if se == nil {
		return fmt.Errorf("session se cannot be nil")
	}

	type result struct {
		resErr error
	}

	resChan := make(chan result)
	go func() {
		var crash error
		defer SilentOnPanic(&crash)

		theErr := se.Run(cmd)
		defer close(resChan)
		resChan <- result{
			resErr: theErr,
		}

	}()

	if timeout != 0 {
		select {
		case res := <-resChan:
			return res.resErr
		case <-time.After(timeout):
			return tunnelError{
				error:       fmt.Errorf(fmt.Sprintf("timeout of %s running command %s", timeout, cmd)),
				isTimeout:   true,
				isTemporary: false,
			}
		}
	}

	res := <-resChan
	return res.resErr
}

func DialSSHWithTimeout(network, addr string, config *ssh.ClientConfig, timeout time.Duration) (
	_ *ssh.Client, err error,
) {
	defer OnPanic(&err)

	type result struct {
		resCli *ssh.Client
		resErr error
	}

	resChan := make(chan result)
	go func() {
		var crash error
		defer SilentOnPanic(&crash)

		theCli, theErr := sshDial(network, addr, config)
		defer close(resChan)
		resChan <- result{
			resCli: theCli,
			resErr: theErr,
		}

	}()

	if timeout != 0 {
		select {
		case res := <-resChan:
			return res.resCli, res.resErr
		case <-time.After(timeout):
			return nil, tunnelError{
				error:       fmt.Errorf(fmt.Sprintf("timeout of %s dialing", timeout)),
				isTimeout:   true,
				isTemporary: false,
			}
		}
	}

	res := <-resChan
	return res.resCli, res.resErr
}

func sshDial(network, addr string, config *ssh.ClientConfig) (_ *ssh.Client, err error) {
	defer OnPanic(&err)

	cl, err := ssh.Dial(network, addr, config)
	if err != nil {
		err = convertErrorToTunnelError(err)
		return nil, err
	}

	return cl, nil
}
