/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"

	"github.com/CS-SI/SafeScale/lib/client"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

var tenantCmdLabel = "tenant"

// TenantCommand command
var TenantCommand = &cli.Command{
	Name:  tenantCmdLabel,
	Usage: "manages tenants",
	Subcommands: []*cli.Command{
		tenantListCommand,
		tenantGetCommand,
		tenantSetCommand,
		tenantInspectCommand,
		tenantScanCommand,
		tenantMetadataCommands,
	},
}

// tenantListCommand handles 'safescale tenant list'
var tenantListCommand = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available tenants",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		tenants, err := clientSession.Tenant.List(temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of tenants", false).Error())))
		}
		return clitools.SuccessResponse(tenants.GetTenants())
	},
}

// tenantGetCommand handles 'safescale tenant get'
var tenantGetCommand = &cli.Command{
	Name:    "get",
	Aliases: []string{"current"},
	Usage:   "Get current tenant",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		tenant, err := clientSession.Tenant.Get(temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "get tenant", false).Error())))
		}
		return clitools.SuccessResponse(tenant)
	},
}

// tenantSetCommand handles 'safescale tenant set'
var tenantSetCommand = &cli.Command{
	Name:  "set",
	Usage: "Set tenant to work with",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Tenant.Set(c.Args().First(), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "set tenant", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

// tenantInspectCommand handles 'safescale tenant inspect'
var tenantInspectCommand = &cli.Command{
	Name:    "inspect",
	Aliases: []string{"show"},
	Usage:   "Inspect tenant",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		resp, err := clientSession.Tenant.Inspect(c.Args().First(), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(resp)
	},
}

// tenantScanCommand handles 'safescale tenant scan' command
var tenantScanCommand = &cli.Command{
	Name:  "scan",
	Usage: "Scan tenant's templates [--dry-run] [--template <template name>]",
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "dry-run", Aliases: []string{"n"}},
		&cli.StringSliceFlag{Name: "template", Aliases: []string{"t"}},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		results, err := clientSession.Tenant.Scan(c.Args().First(), c.Bool("dry-run"), c.StringSlice("template"), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "scan tenant", false).Error())))
		}
		return clitools.SuccessResponse(results.GetResults())
	},
}

const tenantMetadataCmdLabel = "metadata"

// tenantMetadataCommands handles 'safescale tenant metadata' commands
var tenantMetadataCommands = &cli.Command{
	Name:      tenantMetadataCmdLabel,
	Usage:     "manage tenant metadata",
	ArgsUsage: "COMMAND",

	Subcommands: []*cli.Command{
		tenantMetadataUpgradeCommand,
		// tenantMetadataBackupCommand,
		// tenantMetadataRestoreCommand,
		tenantMetadataDeleteCommand,
	},
}

const tenantMetadataUpgradeLabel = "upgrade"

var tenantMetadataUpgradeCommand = &cli.Command{
	Name:  tenantMetadataUpgradeLabel,
	Usage: "Upgrade tenant metadata if needed",
	// Flags: []cli.Flag{
	// 	&cli.BoolFlag{
	// 		Name: "dry-run",
	// 		Aliases: []string{"n"},
	// 	},
	// },
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", tenantCmdLabel, tenantMetadataCmdLabel, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		//dryRun := c.Bool("dry-run")
		results, err := clientSession.Tenant.Upgrade(c.Args().First(), false/*dryRun*/, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "metadata upgrade", false).Error())))
		}
		return clitools.SuccessResponse(results)
	},
}

const tenantMetadataDeleteCmdLabel = "delete"

var tenantMetadataDeleteCommand = &cli.Command{
	Name:    tenantMetadataDeleteCmdLabel,
	Aliases: []string{"remove", "rm", "destroy", "cleanup"},
	Usage:   "Remove SafeScale metadata (making SafeScale unable to manage resources anymore); use with caution",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Tenant.Cleanup(c.Args().First(), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "set tenant", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}
