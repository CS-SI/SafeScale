/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package cmds

import (
	"fmt"
	"os"

	brokerclient "github.com/CS-SI/SafeScale/broker/client"
	clitools "github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/enums/ExitCode"

	pb "github.com/CS-SI/SafeScale/broker"

	"github.com/urfave/cli"
)

var (
	// Verbose tells if user asks more verbosity
	Verbose bool
	// Debug tells if user asks debug information
	Debug bool

	hostName     string
	hostInstance *pb.Host
	featureName  string
)

func extractFeatureArgument(c *cli.Context) error {
	if c.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "Missing mandatory argument FEATURENAME")
		_ = cli.ShowSubcommandHelp(c)
		return clitools.ExitOnInvalidArgument()
	}
	featureName = c.Args().Get(1)
	if featureName == "" {
		fmt.Fprintln(os.Stderr, "Invalid argument FEATURENAME")
		return clitools.ExitOnInvalidArgument()
	}
	return nil
}

// Use the hostnamPos-th argument of the command as a hostName and use it to get the host instance
func extractHostArgument(c *cli.Context, hostnamePos int) error {
	hostName = c.Args().Get(hostnamePos)
	if hostName == "" {
		fmt.Fprintln(os.Stderr, "argument HOSTNAME invalid")
		return clitools.ExitOnInvalidArgument()
	}

	var err error
	hostInstance, err = brokerclient.New().Host.Inspect(hostName, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		return clitools.ExitOnRPC(err.Error())
	}
	if hostInstance == nil {
		return clitools.ExitOnErrorWithMessage(ExitCode.NotFound, fmt.Sprintf("Host '%s' not found.\n", hostName))
	}

	return nil
}
