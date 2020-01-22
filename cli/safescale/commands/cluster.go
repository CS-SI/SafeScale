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
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"

	"github.com/sirupsen/logrus"

	"github.com/urfave/cli"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/cluster"
	"github.com/CS-SI/SafeScale/lib/server/cluster/api"
	"github.com/CS-SI/SafeScale/lib/server/cluster/control"
	clusterpropsv1 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v1"
	clusterpropsv2 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v2"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/complexity"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/flavor"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/property"
	"github.com/CS-SI/SafeScale/lib/server/install"
	"github.com/CS-SI/SafeScale/lib/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
)

var (
	clusterName string
	// clusterServiceName *string
	clusterInstance api.Cluster
)

var clusterCommandName = "cluster"

// ClusterCommand command
var ClusterCommand = cli.Command{
	Name:      "cluster",
	Aliases:   []string{"datacenter", "dc", "platform"},
	Usage:     "create and manage cluster",
	ArgsUsage: "COMMAND",
	Subcommands: []cli.Command{
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
		clusterDcosCommand,
		clusterKubectlCommand,
		clusterHelmCommand,
		clusterListFeaturesCommand,
		clusterCheckFeatureCommand,
		clusterAddFeatureCommand,
		clusterDeleteFeatureCommand,
	},
}

func extractClusterArgument(c *cli.Context) error {
	if !c.Command.HasName("list") || strings.HasSuffix(c.App.Name, " node") || strings.HasSuffix(c.App.Name, " master") {
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument("Missing mandatory argument CLUSTERNAME.")
		}
		clusterName = c.Args().First()
		if clusterName == "" {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument("Invalid argument CLUSTERNAME.")
		}

		var err error
		clusterInstance, err = cluster.Load(concurrency.RootTask(), clusterName)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			if _, ok := err.(*scerr.ErrNotFound); ok {
				if !c.Command.HasName("create") {
					return clitools.ExitOnErrorWithMessage(exitcode.NotFound, fmt.Sprintf("Cluster '%s' not found.", clusterName))
				}
			} else {
				msg := fmt.Sprintf("failed to query for cluster '%s': %s", clusterName, err.Error())
				return clitools.ExitOnRPC(msg)
			}
		} else if c.Command.HasName("create") {
			return clitools.ExitOnErrorWithMessage(exitcode.Duplicate, fmt.Sprintf("Cluster '%s' already exists.", clusterName))
		}
	}

	return nil
}

// clusterListCommand handles 'deploy cluster list'
var clusterListCommand = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available clusters",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		list, err := cluster.List()
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(fmt.Sprintf("failed to get cluster list: %v", err)))
		}

		var formatted []interface{}
		for _, value := range list {
			c, _ := value.(api.Cluster)
			converted, err := convertToMap(c)
			if err != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, fmt.Sprintf("failed to extract data about cluster '%s'", c.GetIdentity(concurrency.RootTask()).Name)))
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
var clusterInspectCommand = cli.Command{
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

		clusterConfig, err := outputClusterConfig()
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}
		return clitools.SuccessResponse(clusterConfig)
	},
}

// outputClusterConfig displays cluster configuration after filtering and completing some fields
func outputClusterConfig() (map[string]interface{}, error) {
	toFormat, err := convertToMap(clusterInstance)
	if err != nil {
		return nil, err
	}
	formatted := formatClusterConfig(toFormat, true)

	return formatted, nil
}

// convertToMap converts clusterInstance to its equivalent in map[string]interface{},
// with fields converted to string and used as keys
func convertToMap(c api.Cluster) (map[string]interface{}, error) {
	identity := c.GetIdentity(concurrency.RootTask())

	result := map[string]interface{}{
		"name":             identity.Name,
		"flavor":           identity.Flavor,
		"flavor_label":     identity.Flavor.String(),
		"complexity":       identity.Complexity,
		"complexity_label": identity.Complexity.String(),
		"admin_login":      "cladm",
		"admin_password":   identity.AdminPassword,
		"keypair":          identity.Keypair,
	}

	properties := c.GetProperties(concurrency.RootTask())
	err := properties.LockForRead(property.CompositeV1).ThenUse(func(v interface{}) error {
		result["tenant"] = v.(*clusterpropsv1.Composite).Tenants[0]
		return nil
	})
	if err != nil {
		return nil, err
	}

	netCfg, err := c.GetNetworkConfig(concurrency.RootTask())
	if err != nil {
		return nil, err
	}
	result["network_id"] = netCfg.NetworkID
	result["cidr"] = netCfg.CIDR
	result["default_route_ip"] = netCfg.DefaultRouteIP
	result["gateway_ip"] = netCfg.DefaultRouteIP // legacy ...
	result["primary_gateway_ip"] = netCfg.GatewayIP
	result["endpoint_ip"] = netCfg.EndpointIP
	result["primary_public_ip"] = netCfg.EndpointIP
	if netCfg.SecondaryGatewayIP != "" {
		result["secondary_gateway_ip"] = netCfg.SecondaryGatewayIP
		result["secondary_public_ip"] = netCfg.SecondaryPublicIP
		result["public_ip"] = netCfg.EndpointIP // legacy ...
	}
	if !properties.Lookup(property.DefaultsV2) {
		err = properties.LockForRead(property.DefaultsV1).ThenUse(func(v interface{}) error {
			defaultsV1, ok := v.(*clusterpropsv1.Defaults)
			if !ok {
				return fmt.Errorf("invalid metadata")
			}
			result["defaults"] = map[string]interface{}{
				"image":  defaultsV1.Image,
				"master": defaultsV1.MasterSizing,
				"node":   defaultsV1.NodeSizing,
			}
			return nil
		})
	} else {
		err = properties.LockForRead(property.DefaultsV2).ThenUse(func(v interface{}) error {
			defaultsV2, _ := v.(*clusterpropsv2.Defaults)
			result["defaults"] = map[string]interface{}{
				"image":   defaultsV2.Image,
				"gateway": defaultsV2.GatewaySizing,
				"master":  defaultsV2.MasterSizing,
				"node":    defaultsV2.NodeSizing,
			}
			return nil
		})
	}
	if err != nil {
		return nil, err
	}

	err = properties.LockForRead(property.NodesV2).ThenUse(func(v interface{}) error {
		nodesV2, ok := v.(*clusterpropsv2.Nodes)
		if !ok {
			return fmt.Errorf("invalid metadata")
		}
		result["nodes"] = map[string]interface{}{
			"masters": nodesV2.Masters,
			"nodes":   nodesV2.PrivateNodes,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = properties.LockForRead(property.FeaturesV1).ThenUse(func(v interface{}) error {
		result["features"] = v.(*clusterpropsv1.Features)
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = properties.LockForRead(property.StateV1).ThenUse(func(v interface{}) error {
		state := v.(*clusterpropsv1.State).State
		result["last_state"] = state
		result["last_state_label"] = state.String()
		return nil
	})
	if err != nil {
		return nil, err
	}
	result["admin_login"] = "cladm"

	// Add information not directly in cluster GetConfig()
	//TODO: replace use of !Disabled["remotedesktop"] with use of Installed["remotedesktop"] (not yet implemented)
	if _, ok := result["features"].(*clusterpropsv1.Features).Disabled["remotedesktop"]; !ok {
		remoteDesktops := map[string][]string{}
		clientHost := client.New().Host
		masters, err := c.ListMasterIDs(concurrency.RootTask())
		if err != nil {
			return nil, err
		}
		for _, id := range masters {
			host, err := clientHost.Inspect(id, temporal.GetExecutionTimeout())
			if err != nil {
				return nil, err
			}
			urlFmt := "https://%s/_platform/remotedesktop/%s/"
			urls := []string{fmt.Sprintf(urlFmt, netCfg.EndpointIP, host.Name)}
			if netCfg.SecondaryPublicIP != "" {
				// VPL: no public VIP IP yet, so don't repeat primary gateway public IP
				// urls = append(urls, fmt.Sprintf(+urlFmt, netCfg.PrimaryPublicIP, host.Name))
				urls = append(urls, fmt.Sprintf(urlFmt, netCfg.SecondaryPublicIP, host.Name))
			}
			remoteDesktops[host.Name] = urls
		}
		result["remote_desktop"] = remoteDesktops
	} else {
		result["remote_desktop"] = fmt.Sprintf("Remote Desktop not installed. To install it, execute 'safescale cluster add-feature %s remotedesktop'.", clusterName)
	}

	return result, nil
}

// clusterCreateCmd handles 'deploy cluster <clustername> create'
var clusterCreateCommand = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create a cluster",
	ArgsUsage: "CLUSTERNAME",

	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "complexity, C",
			Value: "Small",
			Usage: "Defines the sizing of the cluster: Small, Normal, Large",
		},
		cli.StringFlag{
			Name:  "flavor, F",
			Value: "K8S",
			Usage: "Defines the type of the cluster; can be BOH, SWARM, OHPC, DCOS, K8S",
		},
		cli.BoolFlag{
			Name:  "keep-on-failure, k",
			Usage: "If used, the resources are not deleted on failure (default: not set)",
		},
		cli.StringFlag{
			Name:  "cidr, N",
			Value: "192.168.0.0/16",
			Usage: "Defines the CIDR of the network to use with cluster",
		},
		cli.StringSliceFlag{
			Name:  "disable",
			Usage: "Allows to disable addition of default features (can be used several times to disable several features)",
		},
		cli.StringFlag{
			Name:  "os",
			Usage: "Defines the operating system to use",
		},
		cli.StringFlag{
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
		cli.StringFlag{
			Name:  "gw-sizing",
			Usage: `Describe gateway sizing in format "<component><operator><value>[,...] (cf. --sizing for details)`,
		},
		cli.StringFlag{
			Name:  "master-sizing",
			Usage: `Describe master sizing in format "<component><operator><value>[,...]" (cf. --sizing for details)`,
		},
		cli.StringFlag{
			Name:  "node-sizing",
			Usage: `Describe node sizing in format "<component><operator><value>[,...]" (cf. --sizing for details)`,
		},
		cli.UintFlag{
			Name:  "cpu",
			Usage: "DEPRECATED! uses --sizing and friends! Defines the number of cpu of masters and nodes in the cluster",
		},
		cli.Float64Flag{
			Name:  "ram",
			Usage: "DEPRECATED! uses --sizing and friends! Defines the size of RAM of masters and nodes in the cluster (in GB)",
		},
		cli.UintFlag{
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
		comp, err := complexity.Parse(complexityStr)
		if err != nil {
			msg := fmt.Sprintf("Invalid option --complexity|-C: %s", err.Error())
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(msg))
		}

		flavorStr := c.String("flavor")
		fla, err := flavor.Parse(flavorStr)
		if err != nil {
			msg := fmt.Sprintf("Invalid option --flavor|-F: %s", err.Error())
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(msg))
		}

		keep := c.Bool("keep-on-failure")

		cidr := c.String("cidr")

		disable := c.StringSlice("disable")
		disableFeatures := map[string]struct{}{}
		for _, v := range disable {
			disableFeatures[v] = struct{}{}
		}

		los := c.String("os")
		if fla == flavor.DCOS {
			// DCOS forces to use RHEL/CentOS/CoreOS, and we've chosen to use CentOS, so ignore --os option
			los = ""
		}

		var (
			gatewaysDef *pb.HostDefinition
			mastersDef  *pb.HostDefinition
			nodesDef    *pb.HostDefinition
		)
		if c.IsSet("sizing") {
			nodesDef, err = constructPBHostDefinitionFromCLI(c, "sizing")
			if err != nil {
				return err
			}
			gatewaysDef = nodesDef
			mastersDef = nodesDef
		}
		if c.IsSet("gw-sizing") {
			gatewaysDef, err = constructPBHostDefinitionFromCLI(c, "gw-sizing")
			if err != nil {
				return err
			}
		}
		if c.IsSet("master-sizing") {
			mastersDef, err = constructPBHostDefinitionFromCLI(c, "master-sizing")
			if err != nil {
				return err
			}
		}
		if c.IsSet("node-sizing") {
			nodesDef, err = constructPBHostDefinitionFromCLI(c, "node-sizing")
			if err != nil {
				return err
			}
		}

		if gatewaysDef == nil && mastersDef == nil && nodesDef == nil {
			cpu := int32(c.Uint("cpu"))
			ram := float32(c.Float64("ram"))
			disk := int32(c.Uint("disk"))
			gpu := int32(c.Uint("gpu"))

			if cpu > 0 || ram > 0.0 || disk > 0 || los != "" {
				nodesDef = &pb.HostDefinition{
					ImageId: los,
					Sizing: &pb.HostSizing{
						MinCpuCount: cpu,
						MaxCpuCount: cpu * 2,
						MinRamSize:  ram,
						MaxRamSize:  ram * 2.0,
						MinDiskSize: disk,
						GpuCount:    gpu,
					},
				}
				gatewaysDef = nodesDef
				gatewaysDef.Sizing.GpuCount = -1 // Neither GPU for gateways by default ...
				mastersDef = gatewaysDef         // ... nor for masters
			}
		}
		clusterInstance, err := cluster.Create(concurrency.RootTask(), control.Request{
			Name:                    clusterName,
			Complexity:              comp,
			CIDR:                    cidr,
			Flavor:                  fla,
			KeepOnFailure:           keep,
			GatewaysDef:             gatewaysDef,
			MastersDef:              mastersDef,
			NodesDef:                nodesDef,
			DisabledDefaultFeatures: disableFeatures,
		})
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			if clusterInstance != nil {
				cluDel := clusterInstance.Delete(concurrency.RootTask())
				if cluDel != nil {
					logrus.Warnf("Error deleting cluster instance: %s", cluDel)
				}
			}
			msg := fmt.Sprintf("failed to create cluster: %s", err.Error())
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, msg))
		}
		if clusterInstance == nil {
			msg := fmt.Sprintf("failed to create cluster: unknown reason")
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, msg))
		}

		toFormat, err := convertToMap(clusterInstance)
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
var clusterDeleteCommand = cli.Command{
	Name:      "delete",
	Aliases:   []string{"destroy", "remove", "rm"},
	Usage:     "delete CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "assume-yes, yes, y",
		},
		cli.BoolFlag{
			Name: "force, f",
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

		err = clusterInstance.Delete(concurrency.RootTask())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterStopCmd handles 'deploy cluster <clustername> stop'
var clusterStopCommand = cli.Command{
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
		err = clusterInstance.Stop(concurrency.RootTask())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

var clusterStartCommand = cli.Command{
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
		err = clusterInstance.Start(concurrency.RootTask())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterStateCmd handles 'deploy cluster <clustername> state'
var clusterStateCommand = cli.Command{
	Name:      "state",
	Usage:     "state CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		state, err := clusterInstance.GetState(concurrency.RootTask())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("failed to get cluster state: %s", err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}
		return clitools.SuccessResponse(map[string]interface{}{
			"Name":       clusterName,
			"State":      state,
			"StateLabel": state.String(),
		})
	},
}

// clusterExpandCmd handles 'deploy cluster <clustername> expand'
var clusterExpandCommand = cli.Command{
	Name:      "expand",
	Usage:     "expand CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Flags: []cli.Flag{
		cli.UintFlag{
			Name:  "count, n",
			Usage: "Define the number of nodes wanted (default: 1)",
			Value: 1,
		},
		cli.StringFlag{
			Name:  "os",
			Usage: "Define the Operating System wanted",
		},
		cli.UintFlag{
			Name:  "cpu",
			Usage: "Define the number of cpu for new node(s); default: number used at cluster creation",
			Value: 0,
		},
		cli.Float64Flag{
			Name:  "ram",
			Usage: "Define the size of RAM for new node(s) (in GB); default: size used at cluster creation",
			Value: 0.0,
		},
		cli.UintFlag{
			Name:  "disk",
			Usage: "Define the size of system disk for new node(s) (in GB); default: size used at cluster creation",
			Value: 0,
		},
		cli.BoolFlag{
			Name:   "gpu",
			Usage:  "Ask for gpu capable host; default: no",
			Hidden: true,
		},
		cli.StringFlag{
			Name: "node-sizing",
			Usage: `Describe node sizing in format "<component><operator><value>[,...]" where:
	<component> can be cpu, cpufreq, gpu, ram, disk, os
	<operator> can be =,<,> (except for disk where valid operators are only = or >)
	<value> can be an integer (for cpu and disk) or a float (for ram) or an including interval "[<lower value>-<upper value>]"`,
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

		var nodesDef *pb.HostDefinition
		if c.IsSet("node-sizing") {
			nodesDef, err = constructPBHostDefinitionFromCLI(c, "node-sizing")
			if err != nil {
				return err
			}
		}

		if nodesDef == nil {
			cpu := int32(c.Uint("cpu"))
			ram := float32(c.Float64("ram"))
			disk := int32(c.Uint("disk"))
			gpu := int32(c.Uint("gpu"))

			if cpu > 0 || ram > 0.0 || disk > 0 || los != "" {
				nodesDef = &pb.HostDefinition{
					ImageId: los,
					Sizing: &pb.HostSizing{
						MinCpuCount: cpu,
						MaxCpuCount: cpu * 2,
						MinRamSize:  ram,
						MaxRamSize:  ram * 2.0,
						MinDiskSize: disk,
						GpuCount:    gpu,
					},
				}
			}
		}

		hosts, err := clusterInstance.AddNodes(concurrency.RootTask(), count, nodesDef)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(hosts)
	},
}

// clusterShrinkCommand handles 'deploy cluster <clustername> shrink'
var clusterShrinkCommand = cli.Command{
	Name:      "shrink",
	Usage:     "shrink CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Flags: []cli.Flag{
		cli.UintFlag{
			Name:  "count, n",
			Usage: "Define the number of nodes to remove; default: 1",
			Value: 1,
		},
		cli.BoolFlag{
			Name:  "assume-yes, yes, y",
			Usage: "Don't ask deletion confirmation",
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
		present, err := clusterInstance.CountNodes(concurrency.RootTask())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(err)
		}
		if count > present {
			msg := fmt.Sprintf("cannot delete %d node%s, the cluster contains only %d of them", count, countS, present)
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(msg))
		}

		if !yes {
			msg := fmt.Sprintf("Are you sure you want to delete %d node%s from Cluster %s", count, countS, clusterName)
			if !utils.UserConfirmed(msg) {
				return clitools.SuccessResponse("Aborted")
			}
		}

		// fmt.Printf("Deleting %d node%s from Cluster '%s' (this may take a while)...", count, countS, clusterName)
		var msgs []string
		availableMaster, err := clusterInstance.FindAvailableMaster(concurrency.RootTask())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(err)
		}
		for i := uint(0); i < count; i++ {
			err := clusterInstance.DeleteLastNode(concurrency.RootTask(), availableMaster.ID)
			if err != nil {
				err = scerr.FromGRPCStatus(err)
				msgs = append(msgs, fmt.Sprintf("failed to delete node #%d: %s", i+1, err.Error()))
			}
		}
		if len(msgs) > 0 {
			return clitools.FailureResponse(clitools.ExitOnRPC(strings.Join(msgs, "\n")))
		}
		return clitools.SuccessResponse(nil)
	},
}

var clusterDcosCommand = cli.Command{
	Name:      "dcos",
	Category:  "Administrative commands",
	Usage:     "dcos CLUSTERNAME [COMMAND ...]",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		identity := clusterInstance.GetIdentity(concurrency.RootTask())
		if identity.Flavor != flavor.DCOS {
			msg := fmt.Sprintf("Can't call dcos on this cluster, its flavor isn't DCOS (%s)", identity.Flavor.String())
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotApplicable, msg))
		}

		args := c.Args().Tail()
		cmdStr := "sudo -u cladm -i dcos " + strings.Join(args, " ")
		return executeCommand(cmdStr, nil)
	},
}

var clusterKubectlCommand = cli.Command{
	Name:      "kubectl",
	Category:  "Administrative commands",
	Usage:     "kubectl CLUSTERNAME [COMMAND ...]",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		err := extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		clientID := GenerateClientIdentity()
		args := c.Args().Tail()
		filteredArgs := []string{}
		ignoreNext := false
		valuesOnRemote := &RemoteFilesHandler{}
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
							st, err = os.Stat(link)
							if err != nil {
								return cli.NewExitError(err.Error(), 1)
							}
						}

						if localFile != "-" {
							rfi := RemoteFileItem{
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
		cmdStr := `sudo -u cladm -i kubectl`
		if len(filteredArgs) > 0 {
			cmdStr += ` ` + strings.Join(filteredArgs, " ")
		}
		return executeCommand(cmdStr, valuesOnRemote)
	},
}

var clusterHelmCommand = cli.Command{
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

		clientID := GenerateClientIdentity()
		useTLS := " --tls"
		filteredArgs := []string{}
		args := c.Args().Tail()
		ignoreNext := false
		urlRegex := regexp.MustCompile("^(http|ftp)[s]?://")
		valuesOnRemote := &RemoteFilesHandler{}
		for idx, arg := range args {
			if ignoreNext {
				ignoreNext = false
				continue
			}
			ignore := false
			switch arg {
			case "init":
				if idx == 0 {
					return cli.NewExitError("helm init is forbidden", int(ExitCode.InvalidArgument))
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
							st, err = os.Stat(link)
							if err != nil {
								return cli.NewExitError(err.Error(), 1)
							}
						}

						if localFile != "-" {
							rfc := RemoteFileItem{
								Local:  localFile,
								Remote: fmt.Sprintf("%s/helm_values_%d.%s.%d.tmp", utils.TempFolder, idx+1, clientID, time.Now().UnixNano()),
							}
							valuesOnRemote.Add(&rfc)
							filteredArgs = append(filteredArgs, "-f")
							filteredArgs = append(filteredArgs, rfc.Remote)
						} else {
							// data comes from the standard input
							return clitools.ExitOnErrorWithMessage(ExitCode.NotImplemented, "'-f -' is not yet supported")
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
		return executeCommand(cmdStr, valuesOnRemote)
	},
}

var clusterRunCommand = cli.Command{
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

func executeCommand(command string, files *RemoteFilesHandler) error {
	task, err := concurrency.NewTask()
	if err != nil {
		return err
	}

	master, err := clusterInstance.FindAvailableMaster(task)
	if err != nil {
		msg := fmt.Sprintf("No masters found available for the cluster '%s': %v", clusterInstance.GetIdentity(concurrency.RootTask()).Name, err.Error())
		return clitools.ExitOnErrorWithMessage(ExitCode.RPC, msg)
	}

	if files != nil && files.Count() > 0 {
		if !Debug {
			defer files.Cleanup(task, master.Name)
		}
		err = files.Upload(task, master.Name)
		if err != nil {
			return clitools.ExitOnErrorWithMessage(ExitCode.RPC, err.Error())
		}
	}

	safescalessh := client.New().SSH
	retcode, _, _, err := safescalessh.Run(task, master.Name, command, Outputs.DISPLAY, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		msg := fmt.Sprintf("failed to execute command on master '%s': %s", master, err.Error())
		return clitools.ExitOnErrorWithMessage(ExitCode.RPC, msg)
	}
	if retcode != 0 {
		return cli.NewExitError("", retcode)
	}
	return nil
}

// clusterCheckFeaturesCommand handles 'safescale cluster <cluster name or id> list-features'
var clusterListFeaturesCommand = cli.Command{
	Name:      "list-features",
	Aliases:   []string{"list-available-features"},
	Usage:     "list-features",
	ArgsUsage: "",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters",
		},
	},

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", clusterCommandName, c.Command.Name, c.Args())
		features, err := install.ListFeatures("cluster")
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}
		return clitools.SuccessResponse(features)
	},
}

// clusterAddFeatureCommand handles 'deploy cluster add-feature CLUSTERNAME FEATURENAME'
var clusterAddFeatureCommand = cli.Command{
	Name:      "add-feature",
	Aliases:   []string{"install-feature"},
	Usage:     "add-feature CLUSTERNAME FEATURENAME",
	ArgsUsage: "CLUSTERNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters",
		},
		cli.BoolFlag{
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

		feature, err := install.NewFeature(concurrency.RootTask(), featureName)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}
		if feature == nil {
			msg := fmt.Sprintf("failed to find a feature named '%s'", featureName)
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotFound, msg))
		}

		values := install.Variables{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		settings := install.Settings{}
		settings.SkipProxy = c.Bool("skip-proxy")

		target, err := install.NewClusterTarget(concurrency.RootTask(), clusterInstance)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(err)
		}
		results, err := feature.Add(target, values, settings)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("error installing feature '%s' on cluster '%s': %s", featureName, clusterName, err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}
		if !results.Successful() {
			msg := fmt.Sprintf("failed to install feature '%s' on cluster '%s'", featureName, clusterName)
			if Debug || Verbose {
				msg += fmt.Sprintf(":\n%s", results.AllErrorMessages())
			}
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, msg))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterCheckFeatureCommand handles 'deploy cluster check-feature CLUSTERNAME FEATURENAME'
var clusterCheckFeatureCommand = cli.Command{
	Name:      "check-feature",
	Aliases:   []string{"verify-feature"},
	Usage:     "check-feature CLUSTERNAME FEATURENAME",
	ArgsUsage: "CLUSTERNAME FEATURENAME",
	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters",
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
		feature, err := install.NewFeature(concurrency.RootTask(), featureName)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			_, _ = fmt.Fprintln(os.Stderr, err.Error())
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}
		if feature == nil {
			msg := fmt.Sprintf("failed to find a feature named '%s'", featureName)
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotFound, msg))
		}

		values := install.Variables{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		settings := install.Settings{}

		target, err := install.NewClusterTarget(concurrency.RootTask(), clusterInstance)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		results, err := feature.Check(target, values, settings)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("error checking if feature '%s' is installed on '%s': %s", featureName, clusterName, err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}

		if !results.Successful() {
			msg := fmt.Sprintf("Feature '%s' not found on cluster '%s'", featureName, clusterName)
			if Verbose || Debug {
				msg += fmt.Sprintf(":\n%s", results.AllErrorMessages())
			}
			return clitools.FailureResponse(clitools.ExitOnNotFound(msg))
		}
		msg := fmt.Sprintf("Feature '%s' found on cluster '%s'", featureName, clusterName)
		return clitools.SuccessResponse(msg)
	},
}

// clusterFeatureDeleteCommand handles 'deploy host <host name or id> package <pkgname> delete'
var clusterDeleteFeatureCommand = cli.Command{
	Name:      "delete-feature",
	Aliases:   []string{"destroy-feature", "remove-feature", "rm-feature", "uninstall-feature"},
	Usage:     "delete-feature CLUSTERNAME FEATURENAME",
	ArgsUsage: "CLUSTERNAME FEATURENAME",
	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters",
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
		feature, err := install.NewFeature(concurrency.RootTask(), featureName)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}
		if feature == nil {
			msg := fmt.Sprintf("failed to find a feature named '%s'", featureName)
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotFound, msg))
		}

		values := install.Variables{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		settings := install.Settings{}
		// TODO: Reverse proxy rules are not yet purged when feature is removed, but current code
		// will try to apply them... Quick fix: Setting SkipProxy to true prevent this
		settings.SkipProxy = true

		target, err := install.NewClusterTarget(concurrency.RootTask(), clusterInstance)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		results, err := feature.Remove(target, values, settings)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("error uninstalling feature '%s' on '%s': %s\n", featureName, clusterName, err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}
		if !results.Successful() {
			msg := fmt.Sprintf("failed to delete feature '%s' from cluster '%s'", featureName, clusterName)
			if Verbose || Debug {
				msg += fmt.Sprintf(":\n%s\n", results.AllErrorMessages())
			}
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, msg))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterNodeCommand handles 'deploy cluster <name> node'
var clusterNodeCommand = cli.Command{
	Name:      "node",
	Usage:     "manage cluster nodes",
	ArgsUsage: "COMMAND",

	Subcommands: []cli.Command{
		clusterNodeListCommand,
		clusterNodeInspectCommand,
		clusterNodeStartCommand,
		clusterNodeStopCommand,
		clusterNodeStateCommand,
	},
}

// clusterNodeListCommand handles 'deploy cluster node list CLUSTERNAME'
var clusterNodeListCommand = cli.Command{
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

		list, err := clusterInstance.ListNodeIDs(concurrency.RootTask())
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

// formatNodeConfig...
func formatNodeConfig(value interface{}) map[string]interface{} { // nolint
	core, ok := value.(map[string]interface{})
	if !ok {
		return nil
	}

	return core
}

// clusterNodeInspectCmd handles 'deploy cluster <clustername> inspect'
var clusterNodeInspectCommand = cli.Command{
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
var clusterNodeDeleteCommand = &cli.Command{ //nolint
	Name:    "delete",
	Aliases: []string{"destroy", "remove", "rm"},

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "yes, assume-yes, y",
			Usage: "If set, respond automatically yes to all questions",
		},
		cli.BoolFlag{
			Name:  "force, f",
			Usage: "If set, force node deletion no matter what (ie. metadata inconsistency)",
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

		err = clusterInstance.Delete(concurrency.RootTask())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterNodeStopCmd handles 'deploy cluster <clustername> node <nodename> stop'
var clusterNodeStopCommand = cli.Command{
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
var clusterNodeStartCommand = cli.Command{
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
var clusterNodeStateCommand = cli.Command{
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
var clusterMasterCommand = cli.Command{
	Name:      "master",
	Usage:     "manage cluster masters",
	ArgsUsage: "COMMAND",

	Subcommands: []cli.Command{
		clusterMasterListCommand,
	},
}

// clusterMasterListCommand handles 'safescale cluster master list CLUSTERNAME'
var clusterMasterListCommand = cli.Command{
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

		list, err := clusterInstance.ListMasterIDs(concurrency.RootTask())
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
