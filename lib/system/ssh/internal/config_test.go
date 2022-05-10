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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSSH_ConfigClone(t *testing.T) {
	t.Skip("not implemented")
}

func TestSSH_Config_NewEmptyConfig(t *testing.T) {
	in := NewEmptyConfig()
	require.NotNil(t, in)
	require.Nil(t, in.PrimaryGatewayConfig())
	require.Nil(t, in.SecondaryGatewayConfig())
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
	require.NotNil(t, xerr)
	require.Nil(t, first)

	first, xerr = NewConfig("host1", "10.11.12.13", 22, "me", "privatekey")
	require.Nil(t, xerr)
	require.NotNil(t, first)

	require.EqualValues(t, first.Hostname(), "host1")
	require.EqualValues(t, first.IPAddress(), "10.11.12.13")
	require.EqualValues(t, first.Port(), 22)
	require.EqualValues(t, first.User(), "me1")
	require.EqualValues(t, first.PrivateKey(), "privatekey1")
	require.Nil(t, first.PrimaryGatewayConfig())
	require.Nil(t, first.SecondaryGatewayConfig())

	second, xerr := NewConfig("host2", "14.15.16.17", 0, "me2", "privatekey2", first)
	require.Nil(t, xerr)
	require.NotNil(t, second)

	require.EqualValues(t, second.Hostname(), "host2")
	require.EqualValues(t, second.IPAddress(), "14.15.16.17")
	require.EqualValues(t, second.Port(), DefaultPort)
	require.EqualValues(t, second.User(), "me2")
	require.EqualValues(t, second.PrivateKey(), "privatekey2")
	require.EqualValues(t, second.PrimaryGatewayConfig(), first)
	require.Nil(t, second.SecondaryGatewayConfig())

	third, xerr := NewConfig("host3", "18.19.20.21", 8022, "me3", "privatekey3", first, second)
	require.Nil(t, xerr)
	require.NotNil(t, third)

	require.EqualValues(t, third.Hostname(), "host3")
	require.EqualValues(t, third.IPAddress(), "18.19.20.21")
	require.EqualValues(t, third.Port(), 8022)
	require.EqualValues(t, third.User(), "me3")
	require.EqualValues(t, third.PrivateKey(), "privatekey3")
	require.NotNil(t, third.PrimaryGatewayConfig())
	require.NotNil(t, third.SecondaryGatewayConfig())
	require.EqualValues(t, third.GatewayConfig(PrimaryGateway).Hostname(), "host2")
	require.EqualValues(t, third.GatewayConfig(SecondaryGateway).Hostname(), "host3")

}
