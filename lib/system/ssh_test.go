/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/CS-SI/SafeScale/lib/utils"
	"io/ioutil"
	"os/user"
	"strings"
	"testing"

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

	ssh_conf := system.SSHConfig{
		User:       usr.Name,
		Host:       "127.0.0.1",
		Port:       22,
		PrivateKey: string(content),
	}
	cmd, err := ssh_conf.Command("whoami")
	assert.Nil(t, err)
	out, err := cmd.Output() // FIXME Correct this test
	if err != nil {
		t.Skip()
	}
	assert.Nil(t, err)
	assert.Equal(t, usr.Name, strings.Trim(string(out), "\n"))
	gateway := ssh_conf

	if !utils.IsEmpty(gateway) {
		ssh_conf.GatewayConfig = &gateway
		cmd, err := ssh_conf.Command("bash -c whoami")
		assert.Nil(t, err)
		out, err := cmd.Output()
		assert.Nil(t, err)
		assert.Equal(t, usr.Name, strings.Trim(string(out), "\n"))
	}

	if !utils.IsEmpty(gateway) {
		gw := gateway
		ssh_conf.GatewayConfig.GatewayConfig = &gw
		cmd, err := ssh_conf.Command("bash -c whoami")
		assert.Nil(t, err)
		out, err := cmd.Output()
		assert.Nil(t, err)
		assert.Equal(t, usr.Name, strings.Trim(string(out), "\n"))
	}
}
