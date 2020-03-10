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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/lib/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

var (
	clusterName string
	// clusterServiceName *string
	clusterInstance resources.Cluster
)

var clusterCommandName = "cluster"

// ClusterCommand command
var ClusterCommand = &cli.Command{
	Name:      "cluster",
	Aliases:   []string{"datacenter", "dc", "platform"},
	Usage:     "create and manage cluster",
	ArgsUsage: "COMMAND",
	Subcommands: []*cli.Command{
		clusterNodeCommand,
		clusterMasterCommand,
		clusterListCommand,
		clusterCreateCommand,
		clusterDeleteCommand,
		clusterInspectCommand,
		clusterStateCommand,
		clusterRunCommand,
		//clusterSshCommand,
		clusterStartCommand,
		clusterStopCommand,
		clusterExpandCommand,
		clusterShrinkCommand,
		clusterKubectlCommand,
		clusterHelmCommand,
		clusterListFeaturesCommand,
		clusterCheckFeatureCommand,
		clusterAddFeatureCommand,
		clusterRemoveFeatureCommand,
	},
}

func extractClusterArgument(c *cli.Context) error {
	if !c.Command.HasName("list") {
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument("Missing mandatory argument CLUSTERNAME.")
		}
		clusterName = c.Args().First()
		if clusterName == "" {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument("Invalid argument CLUSTERNAME.")
		}
	}

	return nil
}

// clusterListCommand handles 'deploy cluster list'
var clusterListCommand = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available clusters",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())

		list, err := client.New().Cluster.List(temporal.DefaultExecutionTimeout)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "failed to get cluster list", false).Error())))
		}

		var formatted []interface{}
		for _, value := range list.Clusters {
			// c, _ := value.(api.Cluster)
			converted, err := convertToMap(value)
			if err != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, fmt.Sprintf("failed to extract data about cluster '%s'", clusterName)))
			}
			formatted = append(formatted, formatClusterConfig(converted, false))
		}
		return clitools.SuccessResponse(formatted)
	},
}

// formatClusterConfig...
func formatClusterConfig(value interface{}, detailed bool) map[string]interface{} {
	core, _ := value.(map[string]interface{}) // FIXME Unnoticed panic

	delete(core, "keypair")
	if !detailed {
		delete(core, "admin_login")
		delete(core, "admin_password")
		delete(core, "defaults")
		delete(core, "features")
		delete(core, "default_route_ip")
		delete(core, "primary_gateway_ip")
		delete(core, "secondary_gateway_ip")
		delete(core, "network_id")
		delete(core, "nodes")
	}
	return core
}

// clusterInspectCmd handles 'deploy cluster <clustername> inspect'
var clusterInspectCommand = &cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show", "get"},
	Usage:     "inspect CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		cluster, err := client.New().Cluster.Inspect(clusterName, temporal.GetExecutionTimeout())
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.RPC, err.Error()))
		}
		clusterConfig, err := outputClusterConfig(cluster)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}
		return clitools.SuccessResponse(clusterConfig)
	},
}

// outputClusterConfig displays cluster configuration after filtering and completing some fields
func outputClusterConfig(cluster *protocol.ClusterResponse) (map[string]interface{}, error) {
	toFormat, err := convertToMap(cluster)
	if err != nil {
		return nil, err
	}
	formatted := formatClusterConfig(toFormat, true)

	return formatted, nil
}

// FIXME: all the data must comes from lib/client
// convertToMap converts clusterInstance to its equivalent in map[string]interface{},
// with fields converted to string and used as keys
func convertToMap(c *protocol.ClusterResponse) (map[string]interface{}, error) {
	// identity := c.Identity(concurrency.RootTask()

	result := map[string]interface{}{
		"name":             c.GetIdentity().GetName(),
		"flavor":           c.GetIdentity().GetFlavor(),
		"flavor_label":     c.GetIdentity().GetFlavor().String(),
		"complexity":       c.GetIdentity().GetComplexity(),
		"complexity_label": c.GetIdentity().GetComplexity().String(),
		"admin_login":      "cladm",
		"admin_password":   c.GetIdentity().GetAdminPassword(),
		"keypair":          c.GetIdentity().GetSshConfig().GetPrivateKey(),
	}

	properties := c.GetProperties()
	var (
		content  map[string]interface{}
		sgwpubip string
	)
	for _, v := range properties {
		err := json.Unmarshal([]byte(v), &content)
		if err != nil {
			return nil, err
		}
		for propnum, propcont := range content {
			switch propnum {
			case clusterproperty.CompositeV1:
				if tenants, ok := propcont.([]interface{}); ok {
					result["tenant"] = tenants[0]
				}
			case clusterproperty.ControlPlaneV1:
				if cp, ok := propcont.(map[string]interface{}); ok {
					result["controplanevip"] = cp["VIP"]
				}
			case clusterproperty.NetworkV2:
				if net, ok := propcont.(map[string]interface{}); ok {
					result["network_id"] = net["NetworkID"]
					result["cidr"] = net["CIDR"]
					result["default_route_ip"] = net["DefaultRouteIP"]
					result["primary_gateway_ip"] = net["GatewayIP"]
					result["endpoint_ip"] = net["EndpointIP"]
					result["primary_public_ip"] = net["EndpointIP"]
					if sgwpubip, ok = net["SecondaryPublicIP"].(string); ok && sgwpubip != "" {
						result["secondary_gateway_ip"] = net["SecondaryGatewayIP"]
						result["secondary_public_ip"] = sgwpubip
					}
				}
			case clusterproperty.DefaultsV1:
				if _, ok := result["defaults"]; !ok {
					if defaults, ok := propcont.(map[string]interface{}); ok {
						result["defaults"] = map[string]interface{}{
							"image":  defaults["Image"].(string),
							"master": defaults["MasterSizing"],
							"node":   defaults["NodeSizing"],
						}
					}
				}
			case clusterproperty.DefaultsV2:
				if defaults, ok := propcont.(map[string]interface{}); ok {
					result["defaults"] = map[string]interface{}{
						"image":   defaults["Image"],
						"gateway": defaults["GatewaySizing"],
						"master":  defaults["MasterSizing"],
						"node":    defaults["NodeSizing"],
					}
				}
			case clusterproperty.NodesV2:
				if nodes, ok := propcont.(map[string]map[string]interface{}); ok {
					result["nodes"] = map[string]interface{}{
						"masters": nodes["Masters"],
						"nodes":   nodes["PrivateNodes"],
					}
				}
			case clusterproperty.FeaturesV1:
				result["features"] = propcont.(map[string]map[string]interface{})
			case clusterproperty.StateV1:
				if state, ok := propcont.(clusterstate.Enum); ok {
					result["last_state"] = state
					result["last_state_label"] = state.String()
				}
			}
		}
	}
	result["admin_login"] = "cladm"

	// Add information not directly in cluster GetConfig()
	//TODO: replace use of !Disabled["remotedesktop"] with use of Installed["remotedesktop"] (not yet implemented)
	disabled := result["features"].(map[string]interface{})["disabled"].(map[string]string)
	if _, ok := disabled["remotedesktop"]; !ok {
		remoteDesktops := map[string][]string{}
		urlFmt := "https://%s/_platform/remotedesktop/%s/"
		for _, v := range result["nodes"].(map[string]interface{})["masters"].(map[string]interface{}) {
			urls := []string{fmt.Sprintf(urlFmt, result["EndpointIP"], v.(string))}
			if sgwpubip != "" {
				// VPL: no public VIP IP yet, so don't repeat primary gateway public IP
				// urls = append(urls, fmt.Sprintf(+urlFmt, netCfg.PrimaryPublicIP, host.Name))
				urls = append(urls, fmt.Sprintf(urlFmt, sgwpubip, v.(string)))
			}
			remoteDesktops[v.(string)] = urls
		}
		result["remote_desktop"] = remoteDesktops
	} else {
		result["remote_desktop"] = fmt.Sprintf("Remote Desktop not installed. To install it, execute 'safescale cluster add-feature %s remotedesktop'.", clusterName)
	}

	return result, nil
}

// clusterCreateCmd handles 'deploy cluster <clustername> create'
var clusterCreateCommand = &cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create a cluster",
	ArgsUsage: "CLUSTERNAME",

	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "complexity",
			Aliases: []string{"C"},
			Value:   "Small",
			Usage:   "Defines the sizing of the cluster: Small, Normal, Large",
		},
		&cli.StringFlag{
			Name:    "flavor",
			Aliases: []string{"F"},
			Value:   "K8S",
			Usage:   "Defines the type of the cluster; can be BOH, SWARM, OHPC, DCOS, K8S",
		},
		&cli.BoolFlag{
			Name:    "keep-on-failure",
			Aliases: []string{"k"},
			Usage:   "If used, the resources are not deleted on failure (default: not set)",
		},
		&cli.StringFlag{
			Name:    "cidr",
			Aliases: []string{"N"},
			Value:   "192.168.0.0/16",
			Usage:   "Defines the CIDR of the network to use with cluster",
		},
		&cli.StringSliceFlag{
			Name:  "disable",
			Usage: "Allows to disable addition of default features (can be used several times to disable several features)",
		},
		&cli.StringFlag{
			Name:  "os",
			Usage: "Defines the operating system to use",
		},
		&cli.StringFlag{
			Name: "sizing",
			Usage: `Describe sizing for any type of host in format "<component><operator><value>[,...]" where:
	<component> can be cpu, cpufreq, gpu, ram, disk
	<operator> can be =,~,<,<=,>,>= (except for disk where valid operators are only = or >=):
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
		- <ram> is expecting a float as memory size in GB, or an interval with minimum and maximum memory size
		- <disk> is expecting an int as system disk size in GB
	examples:
		--sizing "cpu <= 4, ram <= 10, disk = 100"
		--sizing "cpu ~ 4, ram = [14-32]" (is identical to --sizing "cpu=[4-8], ram=[14-32]")
		--sizing "cpu <= 8, ram ~ 16"
	Can be used with --gw-sizing and friends to set a global host sizing and refine for a particular type of host.
`,
		},
		&cli.StringFlag{
			Name:  "gw-sizing",
			Usage: `Describe gateway sizing in format "<component><operator><value>[,...] (cf. --sizing for details)`,
		},
		&cli.StringFlag{
			Name:  "master-sizing",
			Usage: `Describe master sizing in format "<component><operator><value>[,...]" (cf. --sizing for details)`,
		},
		&cli.StringFlag{
			Name:  "node-sizing",
			Usage: `Describe node sizing in format "<component><operator><value>[,...]" (cf. --sizing for details)`,
		},
		&cli.UintFlag{
			Name:  "cpu",
			Usage: "DEPRECATED! uses --sizing and friends! Defines the number of cpu of masters and nodes in the cluster",
		},
		&cli.Float64Flag{
			Name:  "ram",
			Usage: "DEPRECATED! uses --sizing and friends! Defines the size of RAM of masters and nodes in the cluster (in GB)",
		},
		&cli.UintFlag{
			Name:  "disk",
			Usage: "DEPRECATED! uses --sizing and friends! Defines the size of system disk of masters and nodes (in GB)",
		},
	},

	Action: func(c *cli.Context) (err error) {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err = extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		complexityStr := c.String("complexity")
		comp, err := clustercomplexity.Parse(complexityStr)
		if err != nil {
			msg := fmt.Sprintf("Invalid option --complexity|-C: %s", err.Error())
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(msg))
		}

		flavorStr := c.String("flavor")
		fla, err := clusterflavor.Parse(flavorStr)
		if err != nil {
			msg := fmt.Sprintf("Invalid option --flavor|-F: %s", err.Error())
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(msg))
		}

		keep := c.Bool("keep-on-failure")

		cidr := c.String("cidr")

		disable := c.StringSlice("disable")

		los := c.String("os")

		var (
			globalDef   string
			gatewaysDef string
			mastersDef  string
			nodesDef    string
		)
		if c.IsSet("sizing") {
			globalDef, err = constructHostDefinitionStringFromCLI(c, "sizing")
			if err != nil {
				return err
			}
		}
		if c.IsSet("gw-sizing") {
			gatewaysDef, err = constructHostDefinitionStringFromCLI(c, "gw-sizing")
			if err != nil {
				return err
			}
		}
		if c.IsSet("master-sizing") {
			mastersDef, err = constructHostDefinitionStringFromCLI(c, "master-sizing")
			if err != nil {
				return err
			}
		}
		if c.IsSet("node-sizing") {
			nodesDef, err = constructHostDefinitionStringFromCLI(c, "node-sizing")
			if err != nil {
				return err
			}
		}

		// VPL: logic has to be moved belongside what is commented in constructPBHostDefinitionFromCLI
		// if gatewaysDef == nil && mastersDef == nil && nodesDef == nil {
		// 	cpu := int32(c.Uint("cpu"))
		// 	ram := float32(c.Float64("ram"))
		// 	disk := int32(c.Uint("disk"))
		// 	gpu := int32(c.Uint("gpu"))

		// 	if cpu > 0 || ram > 0.0 || disk > 0 || los != "" {
		// 		nodesDef = &protocol.HostDefinition{
		// 			ImageId: los,
		// 			Sizing: &protocol.HostSizing{
		// 				MinCpuCount: cpu,
		// 				MaxCpuCount: cpu * 2,
		// 				MinRamSize:  ram,
		// 				MaxRamSize:  ram * 2.0,
		// 				MinDiskSize: disk,
		// 				GpuCount:    gpu,
		// 			},
		// 		}
		// 		gatewaysDef = nodesDef
		// 		gatewaysDef.Sizing.GpuCount = -1 // Neither GPU for gateways by default ...
		// 		mastersDef = gatewaysDef         // ... nor for masters
		// 	}
		// }

		req := protocol.ClusterCreateRequest{
			Name:          clusterName,
			Complexity:    protocol.ClusterComplexity(comp),
			Flavor:        protocol.ClusterFlavor(fla),
			KeepOnFailure: keep,
			Cidr:          cidr,
			Disabled:      disable,
			Os:            los,
			GlobalSizing:  globalDef,
			GatewaySizing: gatewaysDef,
			MasterSizing:  mastersDef,
			NodeSizing:    nodesDef,
		}
		res, err := client.New().Cluster.Create(req, temporal.GetLongOperationTimeout())
		// clusterInstance, err := cluster.Create(concurrency.RootTask(), resources.ClusterRequest{
		// 	Name:                    clusterName,
		// 	Complexity:              comp,
		// 	CIDR:                    cidr,
		// 	Flavor:                  fla,
		// 	KeepOnFailure:           keep,
		// 	GatewaysDef:             gatewaysDef,
		// 	MastersDef:              mastersDef,
		// 	MastersCount:            mastersCount,
		// 	NodesCount:              nodesCount,
		// 	NodesDef:                nodesDef,
		// 	DisabledDefaultFeatures: disableFeatures,
		// })
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("failed to create cluster: %s", err.Error())
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, msg))
		}
		if res == nil {
			msg := fmt.Sprintf("failed to create cluster: unknown reason")
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, msg))
		}

		toFormat, err := convertToMap(res)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}

		formatted := formatClusterConfig(toFormat, true)
		if !Debug {
			delete(formatted, "defaults")
		}
		return clitools.SuccessResponse(formatted)
	},
}

// clusterDeleteCmd handles 'deploy cluster <clustername> delete'
var clusterDeleteCommand = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"destroy", "remove", "rm"},
	Usage:     "delete CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "assume-yes",
			Aliases: []string{"yes", "y"},
		},
		&cli.BoolFlag{
			Name:    "force",
			Aliases: []string{"f"},
		},
	},

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		yes := c.Bool("assume-yes")
		force := c.Bool("force")

		if !yes && !utils.UserConfirmed(fmt.Sprintf("Are you sure you want to delete Cluster '%s'", clusterName)) {
			return clitools.SuccessResponse("Aborted")
		}
		if force {
			logrus.Println("'-f,--force' does nothing yet")
		}

		err = client.New().Cluster.Delete(clusterName, temporal.GetLongOperationTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterStopCmd handles 'deploy cluster <clustername> stop'
var clusterStopCommand = &cli.Command{
	Name:      "stop",
	Aliases:   []string{"freeze", "halt"},
	Usage:     "stop CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = client.New().Cluster.Stop(clusterName, temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

var clusterStartCommand = &cli.Command{
	Name:      "start",
	Aliases:   []string{"unfreeze"},
	Usage:     "start CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		clusterRef := c.Args().First()
		err = client.New().Cluster.Start(clusterRef, temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "start of cluster", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterStateCmd handles 'deploy cluster <clustername> state'
var clusterStateCommand = &cli.Command{
	Name:      "state",
	Usage:     "state CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		state, err := client.New().Cluster.GetState(clusterName, temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("failed to get cluster state: %s", err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}
		return clitools.SuccessResponse(map[string]interface{}{
			"Name":       clusterName,
			"State":      state.State,
			"StateLabel": clusterstate.Enum(state.State).String(),
		})
	},
}

// clusterExpandCmd handles 'deploy cluster <clustername> expand'
var clusterExpandCommand = &cli.Command{
	Name:      "expand",
	Usage:     "expand CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Flags: []cli.Flag{
		&cli.UintFlag{
			Name:    "count",
			Aliases: []string{"n"},
			Usage:   "Define the number of nodes wanted (default: 1)",
			Value:   1,
		},
		&cli.StringFlag{
			Name:  "os",
			Usage: "Define the Operating System wanted",
		},
		&cli.StringFlag{
			Name: "node-sizing",
			Usage: `Describe node sizing in format "<component><operator><value>[,...]" where:
	<component> can be cpu, cpufreq, gpu, ram, disk, os
	<operator> can be =,<,> (except for disk where valid operators are only = or >)
	<value> can be an integer (for cpu and disk) or a float (for ram) or an including interval "[<lower value>-<upper value>]"`,
		},
		&cli.UintFlag{
			Name:  "cpu",
			Usage: "DEPRECATED! Define the number of cpu for new node(s); default: number used at cluster creation",
			Value: 0,
		},
		&cli.Float64Flag{
			Name:  "ram",
			Usage: "DEPRECATED! Define the size of RAM for new node(s) (in GB); default: size used at cluster creation",
			Value: 0.0,
		},
		&cli.UintFlag{
			Name:  "disk",
			Usage: "DEPRECATED! Define the size of system disk for new node(s) (in GB); default: size used at cluster creation",
			Value: 0,
		},
		&cli.BoolFlag{
			Name:   "gpu",
			Usage:  "DEPRECATED! Ask for gpu capable host; default: no",
			Hidden: true,
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		count := c.Uint("count")
		if count == 0 {
			count = 1
		}
		los := c.String("os")

		var (
			nodesDef   string
			nodesCount uint
		)
		nodesDef, err = constructHostDefinitionStringFromCLI(c, "node-sizing")
		if err != nil {
			return err
		}
		if nodesCount > count {
			count = nodesCount
		}

		req := protocol.ClusterResizeRequest{
			Name:       clusterName,
			Action:     protocol.ClusterResizeAction_CRA_EXPAND,
			Count:      int32(count),
			NodeSizing: nodesDef,
			ImageId:    los,
		}
		hosts, err := client.New().Cluster.Expand(req, temporal.GetLongOperationTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(hosts)
	},
}

// clusterShrinkCommand handles 'deploy cluster <clustername> shrink'
var clusterShrinkCommand = &cli.Command{
	Name:      "shrink",
	Usage:     "shrink CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Flags: []cli.Flag{
		&cli.UintFlag{
			Name:    "count",
			Aliases: []string{"n"},
			Usage:   "Define the number of nodes to remove; default: 1",
			Value:   1,
		},
		&cli.BoolFlag{
			Name:    "assume-yes",
			Aliases: []string{"yes", "y"},
			Usage:   "Don't ask deletion confirmation",
		},
	},

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		count := c.Uint("count")
		yes := c.Bool("yes")

		var countS string
		if count > 1 {
			countS = "s"
		}

		// VPL: to move inside safescaled
		// present, err := clusterInstance.CountNodes(concurrency.RootTask()
		// if err != nil {
		// 	err = scerr.FromGRPCStatus(err)
		// 	return clitools.FailureResponse(err)
		// }
		// if count > present {
		// 	msg := fmt.Sprintf("cannot delete %d node%s, the cluster contains only %d of them", count, countS, present)
		// 	return clitools.FailureResponse(clitools.ExitOnInvalidOption(msg))
		// }

		if !yes {
			msg := fmt.Sprintf("Are you sure you want to delete %d node%s from Cluster %s", count, countS, clusterName)
			if !utils.UserConfirmed(msg) {
				return clitools.SuccessResponse("Aborted")
			}
		}

		req := protocol.ClusterResizeRequest{
			Name:   clusterName,
			Action: protocol.ClusterResizeAction_CRA_SHRINK,
			Count:  int32(count),
		}
		_, err = client.New().Cluster.Shrink(req, temporal.GetLongOperationTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

var clusterKubectlCommand = &cli.Command{
	Name:      "kubectl",
	Category:  "Administrative commands",
	Usage:     "kubectl CLUSTERNAME [KUBECTL_COMMAND]... [-- [KUBECTL_OPTIONS]...]",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		task, err := concurrency.RootTask()
		if err != nil {
			return clitools.FailureResponse(err)
		}

		clientID := GenerateClientIdentity()
		args := c.Args().Tail()
		var filteredArgs []string
		ignoreNext := false
		valuesOnRemote := &client.RemoteFilesHandler{}
		urlRegex := regexp.MustCompile("^(http|ftp)[s]?://")
		for idx, arg := range args {
			if ignoreNext {
				ignoreNext = false
				continue
			}
			ignore := false
			switch arg {
			case "--":
				ignore = true
			case "-f":
				if idx+1 < len(args) {
					localFile := args[idx+1]
					if localFile != "" {
						// If it's an URL, propagate as-is
						if urlRegex.MatchString(localFile) {
							filteredArgs = append(filteredArgs, "-f")
							filteredArgs = append(filteredArgs, localFile)
							ignore = true
							ignoreNext = true
							continue
						}

						// Check for file
						st, err := os.Stat(localFile)
						if err != nil {
							return cli.NewExitError(err.Error(), 1)
						}
						// If it's a link, get the target of it
						if st.Mode()&os.ModeSymlink == os.ModeSymlink {
							link, err := filepath.EvalSymlinks(localFile)
							if err != nil {
								return cli.NewExitError(err.Error(), 1)
							}
							_, err = os.Stat(link)
							if err != nil {
								return cli.NewExitError(err.Error(), 1)
							}
						}

						if localFile != "-" {
							rfi := client.RemoteFileItem{
								Local:  localFile,
								Remote: fmt.Sprintf("%s/helm_values_%d.%s.%d.tmp", utils.TempFolder, idx+1, clientID, time.Now().UnixNano()),
							}
							valuesOnRemote.Add(&rfi)
							filteredArgs = append(filteredArgs, "-f")
							filteredArgs = append(filteredArgs, rfi.Remote)
						} else {
							// data comes from the standard input
							return clitools.FailureResponse(fmt.Errorf("'-f -' is not yet supported"))
						}
						ignoreNext = true
					}
				}
				ignore = true
			}
			if !ignore {
				filteredArgs = append(filteredArgs, arg)
			}
		}
		cmdStr := "sudo -u cladm -i kubectl"
		if len(filteredArgs) > 0 {
			cmdStr += ` ` + strings.Join(filteredArgs, " ")
		}

		return executeCommand(task, cmdStr, valuesOnRemote, outputs.DISPLAY)
	},
}

var clusterHelmCommand = &cli.Command{
	Name:      "helm",
	Category:  "Administrative commands",
	Usage:     "helm CLUSTERNAME COMMAND [[--][PARAMS ...]]",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		task, err := concurrency.RootTask()
		if err != nil {
			return clitools.FailureResponse(err)
		}

		clientID := GenerateClientIdentity()
		useTLS := " --tls"
		var filteredArgs []string
		args := c.Args().Tail()
		ignoreNext := false
		urlRegex := regexp.MustCompile("^(http|ftp)[s]?://")
		valuesOnRemote := &client.RemoteFilesHandler{}
		for idx, arg := range args {
			if ignoreNext {
				ignoreNext = false
				continue
			}
			ignore := false
			switch arg {
			case "init":
				if idx == 0 {
					return cli.NewExitError("helm init is forbidden", int(exitcode.InvalidArgument))
				}
			case "search", "repo":
				if idx == 0 {
					useTLS = ""
				}
			case "--":
				ignore = true
			case "-f", "--values":
				if idx+1 < len(args) {
					localFile := args[idx+1]
					if localFile != "" {
						// If it's an URL, filter as-is
						if urlRegex.MatchString(localFile) {
							filteredArgs = append(filteredArgs, "-f")
							filteredArgs = append(filteredArgs, localFile)
							ignore = true
							ignoreNext = true
							continue
						}

						// Check for file
						st, err := os.Stat(localFile)
						if err != nil {
							return cli.NewExitError(err.Error(), 1)
						}
						// If it's a link, get the target of it
						if st.Mode()&os.ModeSymlink == os.ModeSymlink {
							link, err := filepath.EvalSymlinks(localFile)
							if err != nil {
								return cli.NewExitError(err.Error(), 1)
							}
							_, err = os.Stat(link)
							if err != nil {
								return cli.NewExitError(err.Error(), 1)
							}
						}

						if localFile != "-" {
							rfc := client.RemoteFileItem{
								Local:  localFile,
								Remote: fmt.Sprintf("%s/helm_values_%d.%s.%d.tmp", utils.TempFolder, idx+1, clientID, time.Now().UnixNano()),
							}
							valuesOnRemote.Add(&rfc)
							filteredArgs = append(filteredArgs, "-f")
							filteredArgs = append(filteredArgs, rfc.Remote)
						} else {
							// data comes from the standard input
							return clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "'-f -' is not yet supported")
						}
						ignoreNext = true
					}
				}
				ignore = true
			}
			if !ignore {
				filteredArgs = append(filteredArgs, arg)
			}
		}
		cmdStr := `sudo -u cladm -i helm ` + strings.Join(filteredArgs, " ") + useTLS

		return executeCommand(task, cmdStr, valuesOnRemote, outputs.DISPLAY)
	},
}

var clusterRunCommand = &cli.Command{
	Name:      "run",
	Aliases:   []string{"execute", "exec"},
	Usage:     "run CLUSTERNAME COMMAND",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "clusterRunCmd not yet implemented"))
	},
}

func executeCommand(task concurrency.Task, command string, files *client.RemoteFilesHandler, outs outputs.Enum) error {
	logrus.Debugf("command=[%s]", command)
	clusterName := clusterInstance.SafeGetName()
	master, err := clusterInstance.FindAvailableMaster(task)
	if err != nil {
		msg := fmt.Sprintf("No masters found available for the cluster '%s': %v", clusterName, err.Error())
		return clitools.ExitOnErrorWithMessage(exitcode.RPC, msg)
	}

	if files != nil && files.Count() > 0 {
		if !Debug {
			defer files.Cleanup(task, master.SafeGetID())
		}
		err = files.Upload(task, master.SafeGetID())
		if err != nil {
			return clitools.ExitOnErrorWithMessage(exitcode.RPC, err.Error())
		}
	}

	sshClient := client.New().SSH
	retcode, stdout, stderr, err := sshClient.Run(task, master.SafeGetID(), command, outs, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		msg := fmt.Sprintf("failed to execute command on master '%s' of cluster '%s': %s", master.SafeGetID(), clusterName, err.Error())
		return clitools.ExitOnErrorWithMessage(exitcode.RPC, msg)
	}
	if retcode != 0 {
		msg := fmt.Sprintf("command executed on master '%s' of cluster '%s' with failure: %s", master.SafeGetID(), clusterName, stdout)
		if stderr != "" {
			if stdout != "" {
				msg += "\n"
			}
			msg += stderr
		}
		return cli.NewExitError(msg, retcode)
	}
	return nil
}

// clusterInstalledFeaturesCommand handles 'safescale cluster <cluster name or id> list-features'
var clusterListFeaturesCommand = &cli.Command{
	Name:      "list-features",
	Aliases:   []string{"list-available-features"},
	Usage:     "list-features",
	ArgsUsage: "",

	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "param",
			Aliases: []string{"p"},
			Usage:   "Allow to define content of feature parameters",
		},
	},

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		task, err := concurrency.RootTask()
		if err != nil {
			return clitools.FailureResponse(err)
		}
		features, err := clusterInstance.ListInstalledFeatures(task)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}
		return clitools.SuccessResponse(features)
	},
}

// clusterAddFeatureCommand handles 'deploy cluster add-feature CLUSTERNAME FEATURENAME'
var clusterAddFeatureCommand = &cli.Command{
	Name:      "add-feature",
	Aliases:   []string{"install-feature"},
	Usage:     "add-feature CLUSTERNAME FEATURENAME",
	ArgsUsage: "CLUSTERNAME FEATURENAME",

	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "param",
			Aliases: []string{"p"},
			Usage:   "Allow to define content of feature parameters",
		},
		&cli.BoolFlag{
			Name:  "skip-proxy",
			Usage: "Disables reverse proxy rules",
		},
	},

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		err = extractFeatureArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		values := map[string]string{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		settings := protocol.FeatureSettings{}
		settings.SkipProxy = c.Bool("skip-proxy")
		err = client.New().Host.AddFeature(hostInstance.Id, featureName, values, settings, 0)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("error adding feature '%s' on host '%s': %s", featureName, hostName, err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterCheckFeatureCommand handles 'deploy cluster check-feature CLUSTERNAME FEATURENAME'
var clusterCheckFeatureCommand = &cli.Command{
	Name:      "check-feature",
	Aliases:   []string{"verify-feature"},
	Usage:     "check-feature CLUSTERNAME FEATURENAME",
	ArgsUsage: "CLUSTERNAME FEATURENAME",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "param",
			Aliases: []string{"p"},
			Usage:   "Allow to define content of feature parameters",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		err = extractFeatureArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		values := map[string]string{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		settings := protocol.FeatureSettings{}
		err = client.New().Host.CheckFeature(hostInstance.Id, featureName, values, settings, 0)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("error checking feature '%s' on host '%s': %s", featureName, hostName, err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}
		msg := fmt.Sprintf("Feature '%s' found on cluster '%s'", featureName, clusterName)
		return clitools.SuccessResponse(msg)
	},
}

// clusterRemoveFeatureCommand handles 'deploy host <host name or id> package <pkgname> delete'
var clusterRemoveFeatureCommand = &cli.Command{
	Name:      "remove-feature",
	Aliases:   []string{"destroy-feature", "delete-feature", "rm-feature", "uninstall-feature"},
	Usage:     "delete-feature CLUSTERNAME FEATURENAME",
	ArgsUsage: "CLUSTERNAME FEATURENAME",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "param",
			Aliases: []string{"p"},
			Usage:   "Allow to define content of feature parameters",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		err = extractFeatureArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		values := map[string]string{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		settings := protocol.FeatureSettings{}
		// TODO: Reverse proxy rules are not yet purged when feature is removed, but current code
		// will try to apply them... Quick fix: Setting SkipProxy to true prevent this
		settings.SkipProxy = true

		err = client.New().Cluster.RemoveFeature(clusterName, featureName, values, settings, 0)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("error removing feature '%s' on host '%s': %s", featureName, hostName, err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterNodeCommand handles 'deploy cluster <name> node'
var clusterNodeCommand = &cli.Command{
	Name:      "node",
	Usage:     "manage cluster nodes",
	ArgsUsage: "COMMAND",

	Subcommands: []*cli.Command{
		clusterNodeListCommand,
		clusterNodeInspectCommand,
		clusterNodeStartCommand,
		clusterNodeStopCommand,
		clusterNodeStateCommand,
		clusterNodeDeleteCommand,
	},
}

// clusterNodeListCommand handles 'deploy cluster node list CLUSTERNAME'
var clusterNodeListCommand = &cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "list CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		hostClt := client.New().Host
		var formatted []map[string]interface{}

		task, err := concurrency.RootTask()
		if err != nil {
			return clitools.FailureResponse(err)
		}
		list, err := clusterInstance.ListNodeIDs(task)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		for _, i := range list {
			host, err := hostClt.Inspect(i, temporal.GetExecutionTimeout())
			if err != nil {
				err = scerr.FromGRPCStatus(err)
				msg := fmt.Sprintf("failed to get data for node '%s': %s. Ignoring.", i, err.Error())
				//fmt.Println(msg)
				logrus.Warnln(msg)
				continue
			}
			formatted = append(formatted, map[string]interface{}{
				"name": host.Name,
			})
		}
		return clitools.SuccessResponse(formatted)
	},
}

// // formatNodeConfig...
// func formatNodeConfig(value interface{}) map[string]interface{} {
// 	core := value.(map[string]interface{})
// 	return core
// }

// clusterNodeInspectCmd handles 'deploy cluster <clustername> inspect'
var clusterNodeInspectCommand = &cli.Command{
	Name:      "inspect",
	Usage:     "node inspect CLUSTERNAME HOSTNAME",
	ArgsUsage: "CLUSTERNAME is the name of the cluster\nHOSTNAME is the hostname of the host resource inside the cluster (ie. for a cluster called 'demo', hostname is 'node-1' and host resourcename is 'demo-node-1')",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		err = extractHostArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		host, err := client.New().Host.Inspect(hostName, temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(host)
	},
}

// clusterNodeDeleteCmd handles 'deploy cluster <clustername> delete'
var clusterNodeDeleteCommand = &cli.Command{
	Name:    "delete",
	Aliases: []string{"destroy", "remove", "rm"},

	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "assume-yes",
			Aliases: []string{"yes", "y"},
			Usage:   "If set, respond automatically yes to all questions",
		},
		&cli.BoolFlag{
			Name:    "force",
			Aliases: []string{"f"},
			Usage:   "If set, force node deletion no matter what (ie. metadata inconsistency)",
		},
	},

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		err = extractHostArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		yes := c.Bool("yes")
		force := c.Bool("force")

		if !yes && !utils.UserConfirmed(fmt.Sprintf("Are you sure you want to delete the node '%s' of the cluster '%s'", hostName, clusterName)) {
			return clitools.SuccessResponse("Aborted")
		}
		if force {
			logrus.Println("'-f,--force' does nothing yet")
		}

		task, err := concurrency.RootTask()
		if err != nil {
			return clitools.FailureResponse(err)
		}
		err = clusterInstance.Delete(task)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterNodeStopCmd handles 'deploy cluster <clustername> node <nodename> stop'
var clusterNodeStopCommand = &cli.Command{
	Name:    "stop",
	Aliases: []string{"freeze"},
	Usage:   "node stop CLUSTERNAME HOSTNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		err = extractHostArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "Not yet implemented"))
	},
}

// clusterNodeStartCmd handles 'deploy cluster <clustername> node <nodename> start'
var clusterNodeStartCommand = &cli.Command{
	Name:    "start",
	Aliases: []string{"unfreeze"},
	Usage:   "node start CLUSTERNAME HOSTNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		err = extractHostArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "Not yet implemented"))
	},
}

// clusterNodeStateCmd handles 'deploy cluster <clustername> state'
var clusterNodeStateCommand = &cli.Command{
	Name:  "state",
	Usage: "node state CLUSTERNAME HOSTNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		err = extractHostArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "Not yet implemented"))
	},
}

// clusterMasterCommand handles 'safescale cluster master ...
var clusterMasterCommand = &cli.Command{
	Name:      "master",
	Usage:     "manage cluster masters",
	ArgsUsage: "COMMAND",

	Subcommands: []*cli.Command{
		clusterMasterListCommand,
	},
}

// clusterMasterListCommand handles 'safescale cluster master list CLUSTERNAME'
var clusterMasterListCommand = &cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "list CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		hostClt := client.New().Host
		var formatted []map[string]interface{}

		task, err := concurrency.RootTask()
		if err != nil {
			return clitools.FailureResponse(err)
		}
		list, err := clusterInstance.ListMasterIDs(task)
		if err != nil {
			return err
		}
		for _, i := range list {
			host, err := hostClt.Inspect(i, temporal.GetExecutionTimeout())
			if err != nil {
				err = scerr.FromGRPCStatus(err)
				msg := fmt.Sprintf("failed to get data for master '%s': %s. Ignoring.", i, err.Error())
				fmt.Println(msg)
				logrus.Warnln(msg)
				continue
			}
			formatted = append(formatted, map[string]interface{}{
				"name": host.Name,
				"id":   host.Id,
			})
		}
		return clitools.SuccessResponse(formatted)
	},
}
