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
	"encoding/json"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

var networkCmdName = "network"

// NetworkCmd command
var NetworkCmd = cli.Command{
	Name:  "network",
	Usage: "network COMMAND",
	Subcommands: []cli.Command{
		networkCreate,
		networkDelete,
		networkInspect,
		networkList,
	},
}

var networkList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List existing Networks (created by SafeScale)",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all",
			Usage: "List all Networks on tenant (not only those created by SafeScale)",
		}},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", networkCmdName, c.Command.Name, c.Args())
		networks, err := client.New().Network.List(c.Bool("all"), temporal.GetExecutionTimeout())
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "list of networks", false).Error())))
		}
		return clitools.SuccessResponse(networks.GetNetworks())
	},
}

var networkDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "delete Network",
	ArgsUsage: "<Network_name> [<Network_name>...]",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", networkCmdName, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Network_name>."))
		}

		var networkList []string
		networkList = append(networkList, c.Args().First())
		networkList = append(networkList, c.Args().Tail()...)

		err := client.New().Network.Delete(networkList, temporal.GetExecutionTimeout())
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "deletion of network", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var networkInspect = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "inspect NETWORK",
	ArgsUsage: "<network_name>",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", networkCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <network_name>."))
		}

		network, err := client.New().Network.Inspect(c.Args().First(), temporal.GetExecutionTimeout())
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "inspection of network", false).Error())))
		}

		// Convert struct to map using struct to json then json to map
		jsoned, err := json.Marshal(network)
		if err != nil {

		}
		mapped := map[string]interface{}{}
		err = json.Unmarshal(jsoned, &mapped)
		if err != nil {

		}
		// Get gateway(s) information (needs the name)
		var pgw, sgw *pb.Host
		pgwID := network.GetGatewayId()
		sgwID := network.GetSecondaryGatewayId()
		pgw, err = client.New().Host.Inspect(pgwID, temporal.GetExecutionTimeout())
		if err != nil {
			mapped["gateway_name"] = pgw.Name
		} else {
			mapped["gateway_name"] = "<unknown>"
		}
		mapped["gateway_name"] = pgw.Name
		if network.GetSecondaryGatewayId() != "" {
			sgw, err = client.New().Host.Inspect(sgwID, temporal.GetExecutionTimeout())
			if err == nil {
				mapped["secondary_gateway_name"] = sgw.Name
			} else {
				mapped["secondary_gateway_name"] = "<unknown>"
			}
		}
		return clitools.SuccessResponse(network)
	},
}

var networkCreate = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create a network",
	ArgsUsage: "<network_name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "cidr",
			Value: "192.168.0.0/24",
			Usage: "cidr of the network",
		},
		cli.StringFlag{
			Name:  "os",
			Value: "Ubuntu 18.04",
			Usage: "Image name for the gateway",
		},
		cli.StringFlag{
			Name:  "gwname",
			Value: "",
			Usage: "Name for the gateway. Default to 'gw-<network_name>'",
		},
		cli.BoolFlag{
			Name:  "failover",
			Usage: "creates 2 gateways for the network with a VIP used a internal default route",
		},
		cli.StringFlag{
			Name: "S, sizing",
			Usage: `Describe sizing of network gateway in format "<component><operator><value>[,...]" where:
			<component> can be cpu, cpufreq, gpu, ram, disk
			<operator> can be =,~,<=,>= (except for disk where valid operators are only = or >=):
				- = means exactly <value>
				- ~ means between <value> and 2*<value>
				- < means strictly lower than <value>
				- <= means lower or equal to <value>
				- > means strictly greater than <value>
				- >= means greater or equal to <value>
			<value> can be an integer (for cpu and disk) or a float (for ram) or an including interval "[<lower value>-<upper value>]:"
				- <cpu> is expecting an int as number of cpu cores, or an interval with minimum and maximum number of cpu cores
				- <cpufreq> is expecting an int as minimum cpu frequency in MHz
				- <gpu> is expecting an int as number of GPU (scanner would have been run first to be able to determine which template proposes GPU)
				- <ram> is expecting a float as memory size in GB, or an interval with minimum and maximum mmory size
				- <disk> is expecting an int as system disk size in GB
			examples:
				--sizing "cpu <= 4, ram <= 10, disk >= 100"
				--sizing "cpu ~ 4, ram = [14-32]" (is identical to --sizing "cpu=[4-8], ram=[14-32]")
				--sizing "cpu <= 8, ram ~ 16"
`,
		},
		cli.UintFlag{
			Name:  "cpu",
			Usage: "DEPRECATED! uses --sizing! Defines the number of cpu of masters and nodes in the cluster",
		},
		cli.Float64Flag{
			Name:  "ram",
			Usage: "DEPRECATED! uses --sizing! Defines the size of RAM of masters and nodes in the cluster (in GB)",
		},
		cli.UintFlag{
			Name:  "disk",
			Usage: "DEPRECATED! uses --sizing! Defines the size of system disk of masters and nodes (in GB)",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", networkCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <network_name>."))
		}

		def, err := constructPBHostDefinitionFromCLI(c, "sizing")
		if err != nil {
			return err
		}
		netdef := pb.NetworkDefinition{
			Cidr:     c.String("cidr"),
			Name:     c.Args().Get(0),
			FailOver: c.Bool("failover"),
			Gateway: &pb.GatewayDefinition{
				ImageId: c.String("os"),
				Name:    c.String("gwname"),
				Sizing:  def.Sizing,
			},
		}
		network, err := client.New().Network.Create(netdef, temporal.GetExecutionTimeout())
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "creation of network", true).Error())))
		}
		return clitools.SuccessResponse(network)
	},
}
