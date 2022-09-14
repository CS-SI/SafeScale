//go:build fixme
// +build fixme

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
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

var userCmdLabel = "user"

// UserCommands command
func UserCommands() *cobra.Command {
	out := &cobra.Command{
		Use:     userCmdLabel,
		Aliases: []string{"account"},
		Short:   "manages Users of SafeScale",
	}
	out.AddCommand(
		userListCommand(),
		userGetCommand(),
		userSetCommand(),
		projectInspectCommand(),
	)
	addPersistentPreRunE(out)
	addCommonFlags(out)
	return out
}

// userListCommand handles 'safescale user list'
func userListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available Projects in Organization",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", userCmdLabel, c.Name(), strings.Join(args, ", "))

			users, err := ClientSession.Users.List(organization, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of organizations", false).Error())))
			}
			return clitools.SuccessResponse(tenants.GetTenants())
		},
	}
	return out
}

// userGetCommand handles 'safescale user get'
func userGetCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "get",
		Aliases: []string{"current"},
		Short:   "Get current SafeScale User for calling user",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", userCmdLabel, c.Name(), strings.Join(args, ", "))

			user, err := ClientSession.Project.Get(organization, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "get current organization", false).Error())))
			}
			return clitools.SuccessResponse(organization)
		},
	}
	return out
}

// userSetCommand handles 'safescale tenant set'
func userSetCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "set",
		Aliases: []string{"default", "current"},
		Short:   "Set default User to use in following SafeScale commands",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)

			if len(args) != 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <user_name>."))
			}

			logrus.Tracef("SafeScale command: %s %s with args '%s'", userCmdLabel, c.Name(), strings.Join(args, ", "))

			err := ClientSession.User.Set(args[0], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "set current project", false).Error())))
			}
			return clitools.SuccessResponse(nil)
		},
	}
	return out
}

// projectInspectCommand handles 'safescale tenant inspect'
func projectInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show"},
		Short:   "Inspect project",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			if len(args) != 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <project_name>."))
			}

			logrus.Tracef("SafeScale command: %s %s with args '%s'", userCmdLabel, c.Name(), strings.Join(args, ", "))

			organization, xerr := extractOrganization(c)
			if xerr != nil {
				return xerr
			}

			resp, err := ClientSession.Project.Inspect(organization, args[0], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
			}

			return clitools.SuccessResponse(resp)
		},
	}
	return out
}
