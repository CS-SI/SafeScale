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
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/stretchr/testify/require"

	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
)

func TestSSH_ConfigClone(t *testing.T) {
	cfg := NewEmptyConfig()
	xerr := cfg.SetHostname("host")
	require.Nil(t, xerr)

	cloned, xerr := cfg.Clone()
	if xerr != nil {
		t.Error(xerr)
	}
	require.NotNil(t, cloned)
	xerr = cloned.SetPrivateKey("changed password")
	require.Nil(t, xerr)

	areEqual := reflect.DeepEqual(cfg, cloned)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, cfg, cloned)
}

func TestSSH_Config_NewEmptyConfig(t *testing.T) {
	in := NewEmptyConfig()
	require.NotNil(t, in)

	gwConf, xerr := in.PrimaryGatewayConfig()
	require.NotNil(t, xerr)
	require.Nil(t, gwConf)

	gwConf, xerr = in.SecondaryGatewayConfig()
	require.NotNil(t, xerr)
	require.Nil(t, gwConf)

	in, xerr = NewConfig("hostname", "10.11.12.13", 80022, "toto", "private key")
	require.Nil(t, xerr)
	require.NotNil(t, in)
	require.False(t, valid.IsNull(in))
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

	first, xerr = NewConfig("host1", "10.11.12.13", 22, "me1", "privatekey1")
	require.Nil(t, xerr)
	require.NotNil(t, first)

	require.EqualValues(t, first.Hostname(), "host1")
	require.EqualValues(t, first.IPAddress(), "10.11.12.13")
	require.EqualValues(t, first.Port(), 22)
	require.EqualValues(t, first.User(), "me1")
	require.EqualValues(t, first.PrivateKey(), "privatekey1")
	gwConf, xerr := first.PrimaryGatewayConfig()
	require.NotNil(t, xerr)
	require.Nil(t, gwConf)
	gwConf, xerr = first.SecondaryGatewayConfig()
	require.NotNil(t, xerr)
	require.Nil(t, gwConf)

	second, xerr := NewConfig("host2", "14.15.16.17", 0, "me2", "privatekey2", first)
	require.Nil(t, xerr)
	require.NotNil(t, second)

	require.EqualValues(t, second.Hostname(), "host2")
	require.EqualValues(t, second.IPAddress(), "14.15.16.17")
	require.EqualValues(t, second.Port(), DefaultPort)
	require.EqualValues(t, second.User(), "me2")
	require.EqualValues(t, second.PrivateKey(), "privatekey2")
	gwConf, xerr = second.PrimaryGatewayConfig()
	require.Nil(t, xerr)
	require.EqualValues(t, gwConf, first)
	gwConf, xerr = second.SecondaryGatewayConfig()
	require.NotNil(t, xerr)
	require.Nil(t, gwConf)

	third, xerr := NewConfig("host3", "18.19.20.21", 8022, "me3", "privatekey3", first, second)
	require.Nil(t, xerr)
	require.NotNil(t, third)

	require.EqualValues(t, third.Hostname(), "host3")
	require.EqualValues(t, third.IPAddress(), "18.19.20.21")
	require.EqualValues(t, third.Port(), 8022)
	require.EqualValues(t, third.User(), "me3")
	require.EqualValues(t, third.PrivateKey(), "privatekey3")

	gwConf, xerr = second.PrimaryGatewayConfig()
	require.Nil(t, xerr)
	require.NotNil(t, gwConf)
	gwConf, xerr = second.SecondaryGatewayConfig()
	require.NotNil(t, xerr)
	require.Nil(t, gwConf)

	gwConf, xerr = third.GatewayConfig(sshapi.PrimaryGateway)
	require.Nil(t, xerr)
	require.EqualValues(t, gwConf.Hostname(), "host1")
	gwConf, xerr = third.GatewayConfig(sshapi.SecondaryGateway)
	require.Nil(t, xerr)
	require.EqualValues(t, gwConf.Hostname(), "host2")
}
