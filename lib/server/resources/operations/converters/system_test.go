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

package converters

import (
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/system"
	"github.com/stretchr/testify/require"
)

func Test_SSHConfigFromSystemToProtocol(t *testing.T) {

	in := &system.SSHConfig{
		Hostname:               "Hostname",
		IPAddress:              "IPAddress",
		Port:                   22,
		User:                   "User",
		PrivateKey:             "PrivateKey",
		LocalPort:              22,
		GatewayConfig:          &system.SSHConfig{},
		SecondaryGatewayConfig: &system.SSHConfig{},
	}
	out := SSHConfigFromSystemToProtocol(in)

	require.EqualValues(t, out.Host, in.IPAddress)
	require.EqualValues(t, out.Port, in.Port)
	require.EqualValues(t, out.PrivateKey, in.PrivateKey)
	require.EqualValues(t, out.User, in.User)

}