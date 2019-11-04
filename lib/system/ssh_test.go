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
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/CS-SI/SafeScale/lib/system"
)

func Test_Command(t *testing.T) {
	usr, err := user.Current()
	assert.Nil(t, err)
	usr.Name = "oscar"

	assert.Nil(t, err)
	content, err := ioutil.ReadFile(fmt.Sprintf("%s/.ssh/test_rsa", usr.HomeDir))
	if err != nil {
		t.Skip()
	}

	require.Nil(t, err)

	ssh_conf := system.SSHConfig{
		User:       "oscar",
		Host:       "127.0.0.1",
		Port:       22,
		PrivateKey: string(content),
	}
	cmd, err := ssh_conf.Command("whoami")
	require.Nil(t, err)
	out, err := cmd.Output()
	require.Nil(t, err)
	require.Equal(t, "oscar", strings.Trim(string(out), "\n"))
	gateway := ssh_conf

	if !utils.IsEmpty(gateway) {
		ssh_conf.GatewayConfig = &gateway
		cmd, err := ssh_conf.Command("bash -c whoami")
		require.Nil(t, err)
		out, err := cmd.Output()
		require.Equal(t, usr.Name, strings.Trim(string(out), "\n"))
	}

	/*
		if !utils.IsEmpty(gateway) {
			ssh_conf.GatewayConfig = &gateway
			cmd, err := ssh_conf.Command("BASH_XTRACEFD=7 ./fuchsia.sh 7> /tmp/captured 2>&1;echo ${PIPESTATUS} > /tmp/errc;cat /tmp/captured;exit `cat /tmp/errc`")
			require.Nil(t, err)
			vibra, err := cmd.Output()
			require.NotNil(t, err)
			fmt.Println(err)
			fmt.Println(string(vibra))
		}

	*/

	if !utils.IsEmpty(gateway) {
		ssh_conf.GatewayConfig = &gateway
		cmd, err := ssh_conf.Command("BASH_XTRACEFD=7 ./fuchsia.sh 7> /tmp/captured 2>&7;echo ${PIPESTATUS} > /tmp/errc;cat /tmp/captured;exit `cat /tmp/errc`")
		require.Nil(t, err)
		errc, vibra, _, err := cmd.RunWithTimeout(context.TODO(), nil, 2*time.Minute)
		if errc != 0 {
			fmt.Println(string(vibra))
		}
		require.True(t, errc != 0)
	}
}
