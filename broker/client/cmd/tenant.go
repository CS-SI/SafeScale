/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

	pb "github.com/CS-SI/SafeScale/broker"
	utils "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/utils/brokeruse"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/urfave/cli"
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
	Name:  "list",
	Usage: "List available tenants",
	Action: func(c *cli.Context) error {
		conn := brokeruse.GetConnection()
		defer conn.Close()
		ctx, cancel := brokeruse.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		tenantService := pb.NewTenantServiceClient(conn)
		tenants, err := tenantService.List(ctx, &google_protobuf.Empty{})
		if err != nil {
			return fmt.Errorf("Could not get tenant list: %v", err)
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
		conn := brokeruse.GetConnection()
		defer conn.Close()
		ctx, cancel := brokeruse.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		tenantService := pb.NewTenantServiceClient(conn)
		tenant, err := tenantService.Get(ctx, &google_protobuf.Empty{})
		if err != nil {
			return fmt.Errorf("Could not get current tenant: %v", err)
		}
		out, _ := json.Marshal(tenant)
		fmt.Println(string(out))

		return nil
	},
}

var tenantSet = cli.Command{
	Name:      "set",
	Usage:     "Set tenant to work with",
	ArgsUsage: "<tenant_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <tenant_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Tenant name required")
		}
		conn := brokeruse.GetConnection()
		defer conn.Close()
		ctx, cancel := brokeruse.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		tenantService := pb.NewTenantServiceClient(conn)
		_, err := tenantService.Set(ctx, &pb.TenantName{Name: c.Args().First()})
		if err != nil {
			return fmt.Errorf("Could not get current tenant: %v", err)
		}
		fmt.Printf("Tenant '%s' set\n", c.Args().First())

		return nil
	},
}
