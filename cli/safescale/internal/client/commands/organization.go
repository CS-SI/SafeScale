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

var organizationCmdLabel = "organization"

// UserCommands command
func OrganizationCommands() *cobra.Command {
	out := &cobra.Command{
		Use:     tenantCmdLabel,
		Aliases: []string{"org"},
		Short:   "manages organizations",
	}
	out.AddCommand(
		organizationListCommand(),
		organizationGetCommand(),
		organizationSetCommand(),
		organizationInspectCommand(),
		organizationSecurityCommands(),
	)
	addPersistentPreRunE(out)
	addCommonFlags(out)
	return out
}

// userListCommand handles 'safescale organization list'
func organizationListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available organizations",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Name(), strings.Join(args, ", "))

			tenants, err := ClientSession.Tenant.List(0)
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
func organizationGetCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "get",
		Aliases: []string{"current"},
		Short:   "Get current organization for calling user",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", organizationCmdLabel, c.Name(), strings.Join(args, ", "))

			organization, err := ClientSession.Organization.Get(0)
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
func organizationSetCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "set",
		Short: "Set organization for calling user",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			if len(args) != 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <organization_name>."))
			}

			logrus.Tracef("SafeScale command: %s %s with args '%s'", organizationCmdLabel, c.Name(), strings.Join(args, ", "))

			err := ClientSession.Organization.Set(args[0], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "set current organization", false).Error())))
			}
			return clitools.SuccessResponse(nil)
		},
	}
	return out
}

// projectInspectCommand handles 'safescale tenant inspect'
func organizationInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show"},
		Short:   "Inspect organization",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			if len(args) != 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <organization_name>."))
			}

			logrus.Tracef("SafeScale command: %s %s with args '%s'", organizationCmdLabel, c.Name(), strings.Join(args, ", "))

			resp, err := ClientSession.Organization.Inspect(args[0], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
			}
			return clitools.SuccessResponse(resp)
		},
	}
	return out
}

const organizationSecurityCmdLabel = "security"

// organizationSecurityCommands handles 'safescale tenant metadata' commands
func organizationSecurityCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   organizationSecurityCmdLabel,
		Short: "manage organization security",
		// ArgsUsage: "COMMAND",
	}
	out.AddCommand(
		organizationSecurityUserCommand(),
	)
	return out
}

const organizationSecurityUserCmdLabel = "user"

func organizationSecurityUserCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   organizationSecurityUserCmdLabel,
		Short: "manage organization users",
		// ArgsUsage: "COMMAND",
	}
	out.AddCommand(
		organizationSecurityUserBindCommand(),
		organizationSecurityUserUnbindCommand(),
	)
	return out
}

func organizationSecurityUserBindCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "bind",
		Short: "Attach a user to the organization",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)

			switch len(args) {
			case 1:
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <user_name>."))
			case 0:
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <organization_name>."))
			default:
			}

			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", organizationCmdLabel, organizationSecurityCmdLabel, organizationSecurityUserCmdLabel, c.Name(), strings.Join(args, ", "))

			// dryRun := c.Flags().GetBool("dry-run")
			results, err := ClientSession.Organization.BindUser(args[0], args[1], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "bind user to organization", false).Error())))
			}
			return clitools.SuccessResponse(results)
		},
	}
	return out
}

func organizationSecurityUserUnbindCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "unbind",
		Aliases: []string{"detach", "remove", "rm"},
		Short:   "Detach an User from an Organization",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)

			switch len(args) {
			case 1:
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <user_name>."))
			case 0:
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments <organization_name> and <user_name>."))
			default:
			}

			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", organizationCmdLabel, organizationSecurityCmdLabel, organizationSecurityUserCmdLabel, c.Name(), strings.Join(args, ", "))

			// dryRun := c.Flags().GetBool("dry-run")
			results, err := ClientSession.Organization.UnbindUser(args[0], args[1], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "bind user to organization", false).Error())))
			}
			return clitools.SuccessResponse(results)
		},
	}
	return out
}
