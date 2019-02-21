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

package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/broker/client"
	"github.com/CS-SI/SafeScale/utils"
	clitools "github.com/CS-SI/SafeScale/utils"
)

// TenantCmd command
var TenantCmd = cli.Command{
	Name:  "tenant",
	Usage: "tenant COMMAND",
	Subcommands: []cli.Command{
		tenantList,
		tenantGet,
		tenantSet,
	},
}

var tenantList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available tenants",
	Action: func(c *cli.Context) error {
		tenants, err := client.New().Tenant.List(client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "list of tenants", false).Error()))
		}
		out, _ := json.Marshal(tenants.GetTenants())
		fmt.Println(string(out))

		return nil
	},
}

var tenantGet = cli.Command{
	Name:  "get",
	Usage: "Get current tenant",
	Action: func(c *cli.Context) error {
		tenant, err := client.New().Tenant.Get(client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "get tenant", false).Error()))
		}
		out, _ := json.Marshal(tenant)
		fmt.Println(string(out))

		return nil
	},
}

var tenantSet = cli.Command{
	Name:  "set",
	Usage: "Set tenant to work with",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <tenant_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		err := client.New().Tenant.Set(c.Args().First(), client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "set tenant", false).Error()))
		}
		fmt.Printf("Tenant '%s' set\n", c.Args().First())
		return nil
	},
}
