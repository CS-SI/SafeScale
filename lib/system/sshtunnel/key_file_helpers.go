/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"io/ioutil"
	"time"

	"golang.org/x/crypto/ssh"
)

// convertToSSHClientConfig converts the given ssh jump configuration into a ssh.ClientConfig
func convertToSSHClientConfig(toConvert *SSHJump, timeout time.Duration) (_ *ssh.ClientConfig, err error) {
	defer OnPanic(&err)

	config := &ssh.ClientConfig{
		User:            toConvert.user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	if len(toConvert.authentication) != 0 {
		config.Auth = toConvert.authentication
		return config, nil
	}

	return config, nil
}

func AuthMethodFromPrivateKeyFile(file string, passphrase []byte) (_ ssh.AuthMethod, err error) {
	defer OnPanic(&err)

	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	return AuthMethodFromPrivateKey(buffer, passphrase)
}

func AuthMethodFromPrivateKey(buffer []byte, passphrase []byte) (_ ssh.AuthMethod, err error) {
	defer OnPanic(&err)

	var signer ssh.Signer

	if passphrase != nil && len(passphrase) != 0 {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(buffer, passphrase)
	} else {
		signer, err = ssh.ParsePrivateKey(buffer)
	}

	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(signer), nil
}
