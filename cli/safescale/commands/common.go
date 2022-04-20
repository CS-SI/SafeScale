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

package commands

import (
	"fmt"

	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v21/lib/client"
	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	clitools "github.com/CS-SI/SafeScale/v21/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v21/lib/utils/cli/enums/exitcode"
)

const (
	DoNotInstanciate = false
	DoInstanciate    = true
)

// extractFeatureArgument returns the name of the feature from the command arguments
func extractFeatureArgument(c *cli.Context) (string, error) {
	if c.NArg() < 2 {
		_ = cli.ShowSubcommandHelp(c)
		return "", clitools.ExitOnInvalidArgument("Missing mandatory argument FEATURENAME")
	}

	featureName := c.Args().Get(1)
	if featureName == "" {
		return "", clitools.ExitOnInvalidArgument("Invalid argument FEATURENAME")
	}

	return featureName, nil
}

// Use the 'hostnamePos'th argument of the command as a host name and use it to get the host instance
func extractHostArgument(c *cli.Context, hostnamePos int, instanciate bool) (string, *protocol.Host, error) {
	hostName := c.Args().Get(hostnamePos)
	if hostName == "" {
		return "", nil, clitools.ExitOnInvalidArgument("argument HOSTNAME invalid")
	}

	var hostInstance *protocol.Host
	if instanciate {
		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return "", nil, clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		var err error
		hostInstance, err = clientSession.Host.Inspect(hostName, 0)
		if err != nil {
			return "", nil, clitools.ExitOnRPC(err.Error())
		}

		if hostInstance == nil {
			return "", nil, clitools.ExitOnErrorWithMessage(exitcode.NotFound, fmt.Sprintf("Host '%s' not found", hostName))
		}
	}

	return hostName, hostInstance, nil
}

// Use the 'nodePos'th argument of the command as a node reference and init hostName with it
func extractNodeArgument(c *cli.Context, nodePos int) (string, error) {
	hostName := c.Args().Get(nodePos)
	if hostName == "" {
		return "", clitools.ExitOnInvalidArgument("argument HOSTNAME invalid")
	}

	return hostName, nil
}
