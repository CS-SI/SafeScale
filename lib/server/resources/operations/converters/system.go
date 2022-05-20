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

// Contains functions that are used to convert from system

import (
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// SSHConfigFromSystemToProtocol converts a system.Config into a SshConfig
func SSHConfigFromSystemToProtocol(from sshapi.Config) (*protocol.SshConfig, fail.Error) {
	var (
		pgw, sgw *protocol.SshConfig
		xerr     fail.Error
	)

	pgwConf, xerr := from.GatewayConfig(sshapi.PrimaryGateway)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
		default:
			return nil, xerr
		}
	}
	if !valid.IsNull(pgwConf) {
		pgw, xerr = SSHConfigFromSystemToProtocol(pgwConf)
		if xerr != nil {
			return nil, xerr
		}
	}

	sgwConf, xerr := from.GatewayConfig(sshapi.SecondaryGateway)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
		default:
			return nil, xerr
		}
	}

	if !valid.IsNull(sgwConf) {
		sgw, xerr = SSHConfigFromSystemToProtocol(sgwConf)
		if xerr != nil {
			return nil, xerr
		}
	}

	out := protocol.SshConfig{
		HostName:         from.Hostname(),
		Host:             from.IPAddress(),
		Port:             int32(from.Port()),
		PrivateKey:       from.PrivateKey(),
		User:             from.User(),
		Gateway:          pgw,
		SecondaryGateway: sgw,
	}
	return &out, nil
}
