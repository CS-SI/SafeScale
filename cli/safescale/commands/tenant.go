/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/CS-SI/SafeScale/lib/client"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

var tenantCmdName = "tenant"

// TenantCmd command
var TenantCmd = &cli.Command{
	Name:  "tenant",
	Usage: "tenant COMMAND",
	Subcommands: []*cli.Command{
		tenantList,
		tenantGet,
		tenantSet,
		tenantCleanup,
	},
}

var tenantList = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available tenants",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", tenantCmdName, c.Command.Name, c.Args())
		tenants, err := client.New().Tenant.List(temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "list of tenants", false).Error())))
		}
		return clitools.SuccessResponse(tenants.GetTenants())
	},
}

var tenantGet = &cli.Command{
	Name:  "get",
	Usage: "Get current tenant",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", tenantCmdName, c.Command.Name, c.Args())
		tenant, err := client.New().Tenant.Get(temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "get tenant", false).Error())))
		}
		return clitools.SuccessResponse(tenant)
	},
}

var tenantSet = &cli.Command{
	Name:  "set",
	Usage: "Set tenant to work with",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", tenantCmdName, c.Command.Name, c.Args())
		err := client.New().Tenant.Set(c.Args().First(), temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "set tenant", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var tenantCleanup = &cli.Command{
	Name:  "set",
	Usage: "Cleanup tenant by removing SafeScale metadata",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", tenantCmdName, c.Command.Name, c.Args())
		err := client.New().Tenant.Cleanup(c.Args().First(), temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "set tenant", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}
