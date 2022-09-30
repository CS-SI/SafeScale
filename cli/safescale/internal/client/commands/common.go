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
	"os"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/schollz/progressbar/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
)

const (
	DoNotInstanciate = false
	DoInstanciate    = true
)

var (
	ClientSession    *cmdline.Session
	CurrentUserState common.State
)

// extractFeatureArgument returns the name of the feature from the command arguments
func extractFeatureArgument(c *cobra.Command, args []string) (string, error) {
	if len(args) < 2 {
		_ = c.Usage()
		return "", cli.ExitOnInvalidArgument("Missing mandatory argument FEATURENAME")
	}

	featureName := args[1]
	if featureName == "" {
		return "", cli.ExitOnInvalidArgument("Invalid argument FEATURENAME")
	}

	return featureName, nil
}

// Use the 'hostnamePos'th argument of the command as a host name and use it to get the host instance
func extractHostArgument(args []string, hostnamePos int, instanciate bool) (string, *protocol.Host, error) {
	hostName := args[hostnamePos]
	if hostName == "" {
		return "", nil, cli.ExitOnInvalidArgument("argument HOSTNAME invalid")
	}

	var hostInstance *protocol.Host
	if instanciate {
		var err error
		hostInstance, err = ClientSession.Host.Inspect(hostName, 0)
		if err != nil {
			return "", nil, cli.ExitOnRPC(err.Error())
		}

		if hostInstance == nil {
			return "", nil, cli.ExitOnErrorWithMessage(exitcode.NotFound, fmt.Sprintf("Host '%s' not found", hostName))
		}
	}

	return hostName, hostInstance, nil
}

// Use the 'nodePos'th argument of the command as a node reference and init hostName with it
func extractNodeArgument(args []string) (string, error) {
	hostName := args[1]
	if hostName == "" {
		return "", cli.ExitOnInvalidArgument("argument HOSTNAME invalid")
	}

	return hostName, nil
}

func interactiveFeedback(description string) func() {
	if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
		pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
		go func() {
			for {
				if pb.IsFinished() {
					return
				}
				err := pb.Add(1)
				if err != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()

		return func() {
			_ = pb.Finish()
		}
	}

	return func() {}
}

func addPersistentPreRunE(in *cobra.Command) {
	var previousCB = in.PersistentPreRunE
	in.PersistentPreRunE = func(c *cobra.Command, args []string) (err error) {
		common.LogSetup("", "cli")

		// Define trace settings of the application (what to trace if trace is wanted)
		// TODO: is it the good behavior ? Shouldn't we fail ?
		// If trace settings cannot be registered, report it but do not fail
		// TODO: introduce use of configuration file with autoreload on change
		err = tracing.RegisterTraceSettings(traceSettings())
		if err != nil {
			logrus.Errorf(err.Error())
		}

		// Create client session
		server, err := c.Flags().GetString("server")
		if err != nil {
			return err
		}

		CurrentUserState, err = common.NewState()
		if err != nil {
			return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}

		err = CurrentUserState.Read()
		if err != nil {
			return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}

		organization := CurrentUserState.Current.Organization
		organizationByFlag, err := c.Flags().GetString("organization")
		if err != nil {
			return err
		}

		if organizationByFlag != "" {
			organization = organizationByFlag
		}
		if organization == "" {
			// FUTURE: error will rise when organization is fully implemented
			// return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, "no organization set"))
		}

		project := CurrentUserState.Current.Project
		projectByFlag, err := c.Flags().GetString("project")
		if err != nil {
			return err
		}

		if projectByFlag != "" {
			project = projectByFlag
		}
		if project == "" {
			// FUTURE: error will rise when project is fully implemented
			// return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, "no project set"))
		}

		tenant := CurrentUserState.Current.Tenant
		tenantByFlag, err := c.Flags().GetString("tenant")
		if err != nil {
			return err
		}

		if tenantByFlag != "" {
			tenant = tenantByFlag
		}

		ClientSession, err = cmdline.NewSession(server, organization, project, tenant)
		if err != nil {
			return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}

		if previousCB != nil {
			err := previousCB(c, args)
			if err != nil {
				return err
			}
		}

		return nil
	}
}

func addCommonFlags(cmd *cobra.Command) {
	flags := cmd.PersistentFlags()
	flags.StringP("server", "L", "localhost:50051", "Connect to backend on server SERVER (default: localhost:50051)")
	flags.StringP("organization", "O", "", "Use organization ORG (default: 'default')")
	flags.StringP("project", "P", "", "Use project PROJECT (default: 'default')")
	flags.StringP("tenant", "T", "", "Use tenant TENANT (default: none)")
	flags.StringP("config", "c", "", "Provides the configuration file to use (if needed) (default: <root-dir>/etc/settings.yml)")
	flags.SetAnnotation("config", cobra.BashCompFilenameExt, global.ValidConfigFilenameExts)
	flags.StringP("root-dir", "R", "", "Defines the root folder of safescale work tree; will overload content of configuration file (default: /opt/safescale)")
	flags.StringP("etc-dir", "E", "", "Defines the config folder of safescale work tree; will overload content of configuration file (default: <root-dir>/etc)")
}
