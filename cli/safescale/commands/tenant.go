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

var tenantCmdName = "tenant"

// TenantCommand command
var TenantCommand = &cli.Command{
	Name:  "tenant",
	Usage: "tenant COMMAND",
	Subcommands: []*cli.Command{
		tenantList,
		tenantGet,
		tenantSet,
		tenantInspect,
		tenantCleanup,
	},
}

var tenantList = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "ErrorList available tenants",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", tenantCmdName, c.Command.Name, c.Args())

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

var tenantGet = &cli.Command{
	Name:    "get",
	Aliases: []string{"current"},
	Usage:   "Get current tenant",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", tenantCmdName, c.Command.Name, c.Args())

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

var tenantSet = &cli.Command{
	Name:  "set",
	Usage: "Set tenant to work with",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", tenantCmdName, c.Command.Name, c.Args())

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

var tenantInspect = &cli.Command{
	Name:    "inspect",
	Aliases: []string{"show"},
	Usage:   "Inspect tenant",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", tenantCmdName, c.Command.Name, c.Args())

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

var tenantCleanup = &cli.Command{
	Name:  "cleanup",
	Usage: "Cleanup tenant by removing SafeScale metadata",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", tenantCmdName, c.Command.Name, c.Args())

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
