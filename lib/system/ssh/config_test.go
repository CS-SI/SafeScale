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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSSH_Config_NewEmptyConfig(t *testing.T) {
	in := NewEmptyConfig()
	require.NotNil(t, in)

	casted, ok := in.(*sshConfig)
	require.True(t, ok)
	require.Nil(t, casted._private.GatewayConfig)
	require.Nil(t, casted._private.SecondaryGatewayConfig)
}

func TestSSH_Config_NewConfig(t *testing.T) {
	first, xerr := NewConfig("", "10.11.12.13", 22, "me", "privatekey")
	require.NotNil(t, xerr)
	require.Nil(t, first)

	first, xerr = NewConfig("host1", "", 22, "me", "privatekey")
	require.NotNil(t, xerr)
	require.Nil(t, first)

	first, xerr = NewConfig("host1", "10.11.12.13", 22, "", "privatekey")
	require.NotNil(t, xerr)
	require.Nil(t, first)

	first, xerr = NewConfig("host1", "10.11.12.13", 22, "me", "")
	require.NotNil(xerr)
	require.Nil(first)

	first, xerr = NewConfig("host1", "10.11.12.13", 22, "me", "privatekey")
	require.Nil(t, xerr)
	require.NotNil(first)

	casted := first.(*sshConfig)
	require.EqualValues(t, casted._private.Hostname, "host1")
	require.EqualValues(t, casted._private.IPAddress, "10.11.12.13")
	require.EqualValues(t, casted._private.Port, 22)
	require.EqualValues(t, casted._private.User, "me1")
	require.EqualValues(t, casted._private.PrivateKey, "privatekey1")
	require.Nil(t, casted._private.GatewayConfig)
	require.Nil(t, casted._private.SecondaryGatewayConfig)

	second, xerr := NewConfig("host2", "14.15.16.17", 0, "me2", "privatekey2", first)
	require.Nil(xerr)
	require.NotNil(second)

	casted = second.(*sshConfig)
	require.EqualValues(t, casted._private.Hostname, "host2")
	require.EqualValues(t, casted._private.IPAddress, "14.15.16.17")
	require.EqualValues(t, casted._private.Port, 22)
	require.EqualValues(t, casted._private.User, "me2")
	require.EqualValues(t, casted._private.PrivateKey, "privatekey2")
	require.EqualValues(t, casted._private.GatewayConfig, first)
	require.Nil(t, casted._private.SecondaryGatewayConfig)

	third, xerr := NewConfig("host3", "18.19.20.21", 8022, "me3", "privatekey3", first, second)
	require.Nil(xerr)
	require.NotNil(third)

	casted := in.(*sshConfig)
	require.EqualValues(t, casted._private.Hostname, "host3")
	require.EqualValues(t, casted._private.IPAddress, "18.19.20.21")
	require.EqualValues(t, casted._private.Port, 8022)
	require.EqualValues(t, casted._private.User, "me3")
	require.EqualValues(t, casted._private.PrivateKey, "privatekey3")
	require.NotNil(t, casted._private.GatewayConfig)
	require.NotNil(t, casted._private.SecondaryGatewayConfig)
	require.EqualValues(t, casted.GatewayConfig().Hostname(), "host2")
	require.EqualValues(t, casted.SecondaryGatewayConfig().Hostname(), "host3")

}
