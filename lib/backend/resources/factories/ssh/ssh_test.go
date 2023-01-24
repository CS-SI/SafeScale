/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/bycli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

func Test_NewConnector(t *testing.T) {

	SetCustomConnectorFactory(nil) // Factory kept when multiple tests

	// Invalid conf
	var config sshapi.Config = nil
	connector, xerr := NewConnector(config, ConnectorWithLib())
	require.Nil(t, connector)
	require.Contains(t, xerr.Error(), "invalid parameter: conf")
	require.Contains(t, xerr.Error(), "cannot be null value")

	// Invalid customFactory
	SetCustomConnectorFactory(func(sshapi.Config) (sshapi.Connector, fail.Error) {
		return nil, fail.NewError("No ssh lib available")
	})
	config = ssh.NewConfig("HostName", "ipAdress", 22, "User", "PrivateKey", 0, "", nil, nil)
	connector, xerr = NewConnector(config, ConnectorWithCli())
	require.Nil(t, connector)
	require.Contains(t, xerr.Error(), "No ssh lib available")

	SetCustomConnectorFactory(nil)

	// Invalid default factory
	var nilcfg sshapi.Config
	connector, xerr = NewConnector(nilcfg, ConnectorWithCli())
	require.Nil(t, connector)
	require.Contains(t, xerr.Error(), "cannot be null")

	// Invalid option
	config = ssh.NewConfig("HostName", "ipAdress", 22, "User", "PrivateKey", 0, "", nil, nil)
	connector, xerr = NewConnector(config, ConnectorWithCli(), nil, func(connector sshapi.Connector, conf sshapi.Config) (sshapi.Connector, fail.Error) {
		return nil, fail.NewError("No ssh lib available")
	})
	require.Nil(t, connector)
	require.Contains(t, xerr.Error(), "No ssh lib available")

	// Valid run
	connector, xerr = NewConnector(config, ConnectorWithCli())
	require.Nil(t, xerr)
	given_conn, xerr := connector.Config()
	require.Nil(t, xerr)
	require.EqualValues(t, config, given_conn)

}

func Test_NewConnector_Cli(t *testing.T) {

	SetCustomConnectorFactory(nil) // Factory kept when multiple tests

	var config sshapi.Config = nil

	// Invalid customFactory
	SetCustomConnectorFactory(func(sshapi.Config) (sshapi.Connector, fail.Error) {
		return nil, fail.NewError("No ssh lib available")
	})
	config = ssh.NewConfig("HostName", "ipAdress", 22, "User", "PrivateKey", 0, "", nil, nil)
	connector, xerr := NewConnector(config, ConnectorWithCli())
	require.Nil(t, connector)
	require.Contains(t, xerr.Error(), "No ssh lib available")

	// Valid custom factory
	SetCustomConnectorFactory(func(config sshapi.Config) (sshapi.Connector, fail.Error) {
		return bycli.NewConnector(config)
	})
	connector, xerr = NewConnector(config, ConnectorWithCli())
	require.Nil(t, xerr)
	given_conn, xerr := connector.Config()
	require.Nil(t, xerr)
	require.EqualValues(t, config, given_conn)

	// In error default factory
	SetCustomConnectorFactory(nil)
	config = nil
	connector, xerr = NewConnector(config, ConnectorWithCli())
	require.Nil(t, connector)
	require.Contains(t, xerr.Error(), "invalid parameter: conf")
	require.Contains(t, xerr.Error(), "cannot be null value")

	// Valid default factory
	config = ssh.NewConfig("HostName", "ipAdress", 22, "User", "PrivateKey", 0, "", nil, nil)
	connector, xerr = NewConnector(config, ConnectorWithCli())
	require.Nil(t, xerr)
	given_conn, xerr = connector.Config()
	require.Nil(t, xerr)
	require.EqualValues(t, config, given_conn)
	require.EqualValues(t, reflect.TypeOf(connector).String(), "*bycli.Profile")

}

func Test_NewConnector_Lib(t *testing.T) {

	SetCustomConnectorFactory(nil) // Factory kept when multiple tests

	var config sshapi.Config = nil

	// Invalid customFactory
	SetCustomConnectorFactory(func(sshapi.Config) (sshapi.Connector, fail.Error) {
		return nil, fail.NewError("No ssh lib available")
	})
	config = ssh.NewConfig("HostName", "ipAdress", 22, "User", "PrivateKey", 0, "", nil, nil)
	connector, xerr := NewConnector(config, ConnectorWithLib())
	require.Nil(t, connector)
	require.Contains(t, xerr.Error(), "No ssh lib available")

	// Valid custom factory
	SetCustomConnectorFactory(func(config sshapi.Config) (sshapi.Connector, fail.Error) {
		return bycli.NewConnector(config)
	})
	connector, xerr = NewConnector(config, ConnectorWithLib())
	require.Nil(t, xerr)
	given_conn, xerr := connector.Config()
	require.Nil(t, xerr)
	require.EqualValues(t, config, given_conn)

	// In error default factory
	SetCustomConnectorFactory(nil)
	config = nil
	connector, xerr = NewConnector(config, ConnectorWithLib())
	require.Nil(t, connector)
	require.Contains(t, xerr.Error(), "invalid parameter: conf")
	require.Contains(t, xerr.Error(), "cannot be null value")

	// Valid default factory
	config = ssh.NewConfig("HostName", "ipAdress", 22, "User", "PrivateKey", 0, "", nil, nil)
	connector, xerr = NewConnector(config, ConnectorWithLib())
	require.Nil(t, xerr)
	given_conn, xerr = connector.Config()
	require.Nil(t, xerr)
	require.EqualValues(t, config, given_conn)
	require.EqualValues(t, reflect.TypeOf(connector).String(), "*bylib.Profile")

}
