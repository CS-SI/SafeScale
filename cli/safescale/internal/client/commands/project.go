//go:build fixme
// +build fixme

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

var projectCmdLabel = "project"

// UserCommands command
func ProjectCommands() *cobra.Command {
	out := &cobra.Command{
		Use:     projectCmdLabel,
		Aliases: []string{"proj"},
		Short:   "manages projects of an organization",
	}
	out.AddCommand(
		projectListCommand(),
		projectGetCommand(),
		projectSetCommand(),
		projectInspectCommand(),
	)
	addPersistentPreRunE(out)
	addCommonFlags(out)
	return out
}

// userListCommand handles 'safescale organization list'
func projectListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available Projects in Organization",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Name(), strings.Join(args, ", "))

			organization, xerr := extractOrganization(c)
			if xerr != nil {
				return xerr
			}

			projects, err := ClientSession.Projects.List(organization, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of organizations", false).Error())))
			}
			return clitools.SuccessResponse(tenants.GetTenants())
		},
	}
	return out
}

// userGetCommand handles 'safescale organization get'
func projectGetCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "get",
		Aliases: []string{"current"},
		Short:   "Get current Project in Organization for calling user",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", projectCmdLabel, c.Name(), strings.Join(args, ", "))

			organization, xerr := extractOrganization(c)
			if xerr != nil {
				return xerr
			}

			project, err := ClientSession.Project.Get(organization, 0)
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
func projectSetCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "set",
		Short: "Set current project in organization for calling user (Organization of the Project becoming also default Organization)",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)

			if len(args) != 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument project_name>."))
			}

			logrus.Tracef("SafeScale command: %s %s with args '%s'", projectCmdLabel, c.Name(), strings.Join(args, ", "))

			organization, xerr := extractOrganization(c)
			if xerr != nil {
				return xerr
			}

			err := ClientSession.Organization.Set(args[0], 0)
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

			logrus.Tracef("SafeScale command: %s %s with args '%s'", projectCmdLabel, c.Name(), strings.Join(args, ", "))

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
