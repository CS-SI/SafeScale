/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
)

// TenantCmd command
var TenantCmd = cli.Command{
	Name:  "tenant",
	Usage: "tenant COMMAND",
	Subcommands: []cli.Command{
		tenantList,
		tenantGet,
		tenantSet,
		tenantStorageList,
		tenantStorageGet,
		tenantStorageSet,
	},
}

var tenantList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available tenants",
	Action: func(c *cli.Context) error {
		tenants, err := client.New().Tenant.List(client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "list of tenants", false).Error())))
		}
		return clitools.SuccessResponse(tenants.GetTenants())
	},
}

var tenantGet = cli.Command{
	Name:  "get",
	Usage: "Get current tenant",
	Action: func(c *cli.Context) error {
		tenant, err := client.New().Tenant.Get(client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "get tenant", false).Error())))
		}
		return clitools.SuccessResponse(tenant)
	},
}

var tenantSet = cli.Command{
	Name:  "set",
	Usage: "Set tenant to work with",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <tenant_name>."))
		}

		err := client.New().Tenant.Set(c.Args().First(), client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "set tenant", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var tenantStorageList = cli.Command{
	Name:    "storage-list",
	Aliases: []string{"storage-ls"},
	Usage:   "List available storage tenants",
	Action: func(c *cli.Context) error {
		tenants, err := client.New().Tenant.StorageList(client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "list of storage tenants", false).Error())))
		}
		return clitools.SuccessResponse(tenants.GetTenants())
	},
}

var tenantStorageGet = cli.Command{
	Name:  "storage-get",
	Usage: "Get current storage tenants",
	Action: func(c *cli.Context) error {
		tenants, err := client.New().Tenant.StorageGet(client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "get storage tenants", false).Error())))
		}
		return clitools.SuccessResponse(tenants.GetNames())
	},
}

var tenantStorageSet = cli.Command{
	Name:      "storage-set",
	Usage:     "Set storage tenants to work with",
	ArgsUsage: "<storage_tenants...>",
	Action: func(c *cli.Context) error {
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <storage_tenants...>."))
		}
		tenantNames := []string{c.Args().First()}
		tenantNames = append(tenantNames, c.Args().Tail()...)
		err := client.New().Tenant.StorageSet(tenantNames, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "set storage tenants", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}
