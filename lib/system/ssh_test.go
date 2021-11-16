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

package system_test

import (
	"fmt"
	"io/ioutil"
	"os/user"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"

	"github.com/stretchr/testify/assert"

	"github.com/CS-SI/SafeScale/lib/system"
)

func Test_Command(t *testing.T) {
	usr, err := user.Current()
	assert.Nil(t, err)
	content, err := ioutil.ReadFile(fmt.Sprintf("%s/.ssh/id_rsa", usr.HomeDir))
	if err != nil {
		t.Skip()
	}

	assert.Nil(t, err)

	sshConf := system.SSHConfig{
		User:       usr.Name,
		IPAddress:  "127.0.0.1",
		Hostname:   "localhost",
		Port:       22,
		PrivateKey: string(content),
	}
	voidtask, err := concurrency.NewTask()
	assert.Nil(t, err)
	{
		sshCmd, err := sshConf.NewCommand(voidtask.Context(), "whoami")
		assert.Nil(t, err)
		out, err := sshCmd.Output() // FIXME: Correct this test
		defer func() { _ = sshCmd.Close() }()
		if err != nil {
			t.Skip()
		}
		assert.Nil(t, err)
		assert.Equal(t, usr.Name, strings.Trim(string(out), "\n"))
	}
	gateway := sshConf

	if !utils.IsEmpty(gateway) {
		sshConf.GatewayConfig = &gateway
		cmd, err := sshConf.NewCommand(voidtask.Context(), "bash -c whoami")
		assert.Nil(t, err)
		defer func() { _ = cmd.Close() }()
		out, err := cmd.Output()
		assert.Nil(t, err)
		assert.Equal(t, usr.Name, strings.Trim(string(out), "\n"))
	}

	if !utils.IsEmpty(gateway) {
		gw := gateway
		sshConf.GatewayConfig.GatewayConfig = &gw
		cmd, err := sshConf.NewCommand(voidtask.Context(), "bash -c whoami")
		assert.Nil(t, err)
		defer func() { _ = cmd.Close() }()
		out, err := cmd.Output()
		assert.Nil(t, err)
		assert.Equal(t, usr.Name, strings.Trim(string(out), "\n"))
	}
}
