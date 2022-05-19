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
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/internal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ConvertInternalToApiConfig ...
func ConvertInternalToApiConfig(conf internal.Config) (sshapi.Config, fail.Error) {
	var gws []sshapi.Config

	gwConf, xerr := conf.PrimaryGatewayConfig()
	if xerr != nil {
		return nil, xerr
	}
	gws[0] = gwConf

	{
		gwConf, xerr := conf.SecondaryGatewayConfig()
		if xerr != nil {
			return nil, xerr
		}
		gws[1] = gwConf
	}

	return ssh.NewConfig(conf.Hostname(), conf.IPAddress(), conf.Port(), conf.User(), conf.PrivateKey(), gws...)
}
