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
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/lib/client"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

var tenantCmdLabel = "tenant"

// TenantCommand command
var TenantCommand = cli.Command{
	Name:  tenantCmdLabel,
	Usage: "manages tenants",
	Subcommands: cli.Commands{
		tenantListCommand,
		tenantGetCommand,
		tenantSetCommand,
		tenantInspectCommand,
		tenantScanCommand,
		tenantMetadataCommands,
	},
}

// tenantListCommand handles 'safescale tenant list'
var tenantListCommand = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available tenants",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Command.Name, c.Args())

		defer interactiveFeedback("Listing tenants")()

		tenants, err := ClientSession.Tenant.List(0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of tenants", false).Error())))
		}
		return clitools.SuccessResponse(tenants.GetTenants())
	},
}

// tenantGetCommand handles 'safescale tenant get'
var tenantGetCommand = cli.Command{
	Name:    "get",
	Aliases: []string{"current"},
	Usage:   "Get current tenant",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Command.Name, c.Args())

		defer interactiveFeedback("Getting current tenant")()

		tenant, err := ClientSession.Tenant.Get(0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "get tenant", false).Error())))
		}
		return clitools.SuccessResponse(tenant)
	},
}

// tenantSetCommand handles 'safescale tenant set'
var tenantSetCommand = cli.Command{
	Name:  "set",
	Usage: "Set tenant to work with",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Command.Name, c.Args())

		defer interactiveFeedback("Setting tenant")()

		err := ClientSession.Tenant.Set(c.Args().First(), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "set tenant", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

// tenantInspectCommand handles 'safescale tenant inspect'
var tenantInspectCommand = cli.Command{
	Name:    "inspect",
	Aliases: []string{"show"},
	Usage:   "Inspect tenant",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Command.Name, c.Args())

		resp, err := ClientSession.Tenant.Inspect(c.Args().First(), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}

		return clitools.SuccessResponse(resp)
	},
}

// tenantScanCommand handles 'safescale tenant scan' command
var tenantScanCommand = cli.Command{
	Name:  "scan",
	Usage: "Scan tenant's templates [--dry-run] [--template <template name>]",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "dry-run, n",
		},
		cli.StringSliceFlag{
			Name: "template, t",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Command.Name, c.Args())

		results, err := ClientSession.Tenant.Scan(c.Args().First(), c.Bool("dry-run"), c.StringSlice("template"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "scan tenant", false).Error())))
		}

		return clitools.SuccessResponse(results.GetResults())
	},
}

const tenantMetadataCmdLabel = "metadata"

// tenantMetadataCommands handles 'safescale tenant metadata' commands
var tenantMetadataCommands = cli.Command{
	Name:      tenantMetadataCmdLabel,
	Usage:     "manage tenant metadata",
	ArgsUsage: "COMMAND",

	Subcommands: cli.Commands{
		tenantMetadataUpgradeCommand,
		// tenantMetadataBackupCommand,
		// tenantMetadataRestoreCommand,
		tenantMetadataDeleteCommand,
	},
}

const tenantMetadataUpgradeLabel = "upgrade"

var tenantMetadataUpgradeCommand = cli.Command{
	Name:  tenantMetadataUpgradeLabel,
	Usage: "Upgrade tenant metadata if needed",
	// Flags: []cli.Flag{
	// 	cli.BoolFlag{
	// 		Name: "dry-run",
	// 		Aliases: []string{"n"},
	// 	},
	// },
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", tenantCmdLabel, tenantMetadataCmdLabel, c.Command.Name, c.Args())

		// dryRun := c.Bool("dry-run")
		results, err := ClientSession.Tenant.Upgrade(c.Args().First(), false /*dryRun*/, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "metadata upgrade", false).Error())))
		}

		return clitools.SuccessResponse(results)
	},
}

const tenantMetadataDeleteCmdLabel = "delete"

var tenantMetadataDeleteCommand = cli.Command{
	Name:    tenantMetadataDeleteCmdLabel,
	Aliases: []string{"remove", "rm", "destroy", "cleanup"},
	Usage:   "Remove SafeScale metadata (making SafeScale unable to manage resources anymore); use with caution",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Command.Name, c.Args())

		err := ClientSession.Tenant.Cleanup(c.Args().First(), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "set tenant", false).Error())))
		}

		return clitools.SuccessResponse(nil)
	},
}
