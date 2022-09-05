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
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

var tenantCmdLabel = "tenant"

// TenantCommands command
func TenantCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   tenantCmdLabel,
		Short: "manages tenants",
	}
	out.AddCommand(
		tenantListCommand(),
		tenantGetCommand(),
		tenantSetCommand(),
		tenantInspectCommand(),
		tenantScanCommand(),
		tenantMetadataCommands(),
	)
	addPersistentPreRunE(out)
	addCommonFlags(out)
	return out
}

// tenantListCommand handles 'safescale tenant list'
func tenantListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available tenants",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Name(), strings.Join(args, ", "))

			tenants, err := ClientSession.Tenant.List(0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of tenants", false).Error())))
			}
			return cli.SuccessResponse(tenants.GetTenants())
		},
	}
	return out
}

// tenantGetCommand handles 'safescale tenant get'
func tenantGetCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "get",
		Aliases: []string{"current"},
		Short:   "Get current tenant",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Name(), strings.Join(args, ", "))

			tenant, err := ClientSession.Tenant.Get(0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "get tenant", false).Error())))
			}
			return cli.SuccessResponse(tenant)
		},
	}
	return out
}

// tenantSetCommand handles 'safescale tenant set'
func tenantSetCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "set",
		Short: "Set tenant to work with",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
			}

			logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Name(), strings.Join(args, ", "))

			err := ClientSession.Tenant.Set(args[0], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "set tenant", false).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}
	return out
}

// tenantInspectCommand handles 'safescale tenant inspect'
func tenantInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show"},
		Short:   "Inspect tenant",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
			}

			logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Name(), strings.Join(args, ", "))

			resp, err := ClientSession.Tenant.Inspect(args[0], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}
			return cli.SuccessResponse(resp)
		},
	}
	return out
}

// tenantScanCommand handles 'safescale tenant scan' command
func tenantScanCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "scan",
		Short: "Scan tenant's templates [--dry-run] [--template <template name>]",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
			}

			logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Name(), strings.Join(args, ", "))

			dryRun, err := c.Flags().GetBool("dry-run")
			if err != nil {
				return cli.FailureResponse(err)
			}

			template, err := c.Flags().GetStringSlice("template")
			if err != nil {
				return cli.FailureResponse(err)
			}

			results, err := ClientSession.Tenant.Scan(args[0], dryRun, template, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "scan tenant", false).Error())))
			}

			return cli.SuccessResponse(results.GetResults())
		},
	}

	flags := out.Flags()
	flags.BoolP("dry-run", "n", false, "do not apply")
	flags.StringSliceP("template", "t", nil, "")

	return out
}

const tenantMetadataCmdLabel = "metadata"

// tenantMetadataCommands handles 'safescale tenant metadata' commands
func tenantMetadataCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   tenantMetadataCmdLabel,
		Short: "manage tenant metadata",
		// ArgsUsage: "COMMAND",
	}
	out.AddCommand(
		tenantMetadataUpgradeCommand(),
		// tenantMetadataBackupCommand(),
		// tenantMetadataRestoreCommand(),
		tenantMetadataDeleteCommand(),
	)
	return out
}

const tenantMetadataUpgradeLabel = "upgrade"

func tenantMetadataUpgradeCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   tenantMetadataUpgradeLabel,
		Short: "Upgrade tenant metadata if needed",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
			}

			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", tenantCmdLabel, tenantMetadataCmdLabel, c.Name(), strings.Join(args, ", "))

			// dryRun := c.Flags().GetBool("dry-run")
			results, err := ClientSession.Tenant.Upgrade(args[0], false /*dryRun*/, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "metadata upgrade", false).Error())))
			}
			return cli.SuccessResponse(results)
		},
	}

	// Flags: []cli.Flag{
	// 	&cli.BoolFlag{
	// 		Name: "dry-run",
	// 		Aliases: []string{"n"},
	// 	},
	// },

	return out
}

const tenantMetadataDeleteCmdLabel = "delete"

func tenantMetadataDeleteCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     tenantMetadataDeleteCmdLabel,
		Aliases: []string{"remove", "rm", "destroy", "cleanup"},
		Short:   "Remove SafeScale metadata (making SafeScale unable to manage resources anymore); use with caution",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
			}

			logrus.Tracef("SafeScale command: %s %s with args '%s'", tenantCmdLabel, c.Name(), strings.Join(args, ", "))

			err := ClientSession.Tenant.Cleanup(args[0], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "set tenant", false).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}
	return out
}
