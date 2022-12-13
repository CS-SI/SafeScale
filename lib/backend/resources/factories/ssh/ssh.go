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
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/bycli"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/bylib"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

var customFactory func(sshapi.Config) (sshapi.Connector, fail.Error)

type Option func(connector sshapi.Connector, conf sshapi.Config) (sshapi.Connector, fail.Error)

func ConnectorWithCli() Option { // nolint
	return func(connector sshapi.Connector, conf sshapi.Config) (sshapi.Connector, fail.Error) {
		if customFactory != nil {
			return customFactory(conf)
		}

		altconnector, xerr := bycli.NewConnector(conf)
		if xerr != nil {
			return nil, xerr
		}

		return altconnector, nil
	}
}

func ConnectorWithLib() Option { // nolint
	return func(connector sshapi.Connector, conf sshapi.Config) (sshapi.Connector, fail.Error) {
		if customFactory != nil {
			return customFactory(conf)
		}

		altconnector, xerr := bylib.NewConnector(conf)
		if xerr != nil {
			return nil, xerr
		}

		return altconnector, nil
	}
}

// NewConnector creates a connector using the factory
func NewConnector(conf sshapi.Config, options ...Option) (sshapi.Connector, fail.Error) {
	if valid.IsNull(conf) {
		return nil, fail.InvalidParameterError("conf", "cannot be null value of 'ssh.Config'")
	}

	if customFactory != nil {
		return customFactory(conf)
	}

	current, xerr := defaultSSHConnectorFactory(conf)
	if xerr != nil {
		return nil, xerr
	}

	for _, op := range options {
		if op != nil {
			current, xerr = op(current, conf)
			if xerr != nil {
				return nil, xerr
			}
		}
	}

	return current, nil
}

func SetCustomConnectorFactory(custom func(sshapi.Config) (sshapi.Connector, fail.Error)) {
	customFactory = custom
}
