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
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/internal"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/internal/bycli"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/internal/bylib"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// NewCliConnector creates a new instance of cliConnector (which follows interfface Connector)
func NewCliConnector(conf api.Config) (api.Connector, fail.Error) {
	if valid.IsNull(conf) {
		return nil, fail.InvalidParameterError("conf", "cannot be null value of 'ssh.Config'")
	}

	return bycli.NewConnector(conf)

}

// NewLibConnector creates a new instance of cliConnector (which follows interface Connector)
func NewLibConnector(conf api.Config) (api.Connector, fail.Error) {
	if valid.IsNull(conf) {
		return nil, fail.InvalidParameterError("conf", "cannot be null value of 'ssh.Config'")
	}

	return bylib.NewConnector(conf)
}

// NewEmptyConfig instanciates a sshConfig instance
func NewEmptyConfig() api.Config {
	return internal.NewEmptyConfig()
}

// NewConfig ...
func NewConfig(hostname, ipAddress string, port uint, user, privateKey string, gws ...api.Config) (api.Config, fail.Error) {
	return internal.NewConfig(hostname, ipAddress, port, user, privateKey, gws...)
}
