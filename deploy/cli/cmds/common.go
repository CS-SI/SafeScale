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
	"github.com/CS-SI/SafeScale/deploy/cli/enums/ExitCode"

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
		return exitError("Missing mandatory argument FEATURENAME", ExitCode.InvalidArgument)
	}
	featureName = c.Args().Get(1)
	if featureName == "" {
		return exitError("Invalid argument FEATURENAME", ExitCode.InvalidArgument)
	}
	return nil
}

// exitError ...
func exitError(msg string, exitcode ExitCode.Enum) error {
	return cli.NewExitError(msg, int(exitcode))
}
