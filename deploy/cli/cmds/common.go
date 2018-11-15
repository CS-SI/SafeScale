/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

	clitools "github.com/CS-SI/SafeScale/utils"

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
