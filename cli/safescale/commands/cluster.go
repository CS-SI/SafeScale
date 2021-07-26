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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

var (
	clusterName string
)

const clusterCmdLabel = "cluster"

// ClusterCommand command
var ClusterCommand = &cli.Command{
	Name:      "cluster",
	Aliases:   []string{"datacenter", "dc", "platform"},
	Usage:     "create and manage cluster",
	ArgsUsage: "COMMAND",
	Subcommands: []*cli.Command{
		clusterNodeCommands,
		clusterMasterCommands,
		clusterFeatureCommands,
		clusterListCommand,
		clusterCreateCommand,
		clusterDeleteCommand,
		clusterInspectCommand,
		clusterStateCommand,
		clusterRunCommand,
		// clusterSshCommand,
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
		clusterFeatureCommands,
	},
}

// clusterListCommand handles 'deploy cluster list'
var clusterListCommand = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "ErrorList available clusters",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		list, err := clientSession.Cluster.List(temporal.DefaultExecutionTimeout)
		if err != nil {
			err := fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "failed to get cluster list", false).Error())))
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

// formatClusterConfig removes unneeded entry from config
func formatClusterConfig(config map[string]interface{}, detailed bool) map[string]interface{} {
	if !detailed {
		delete(config, "admin_login")
		delete(config, "admin_password")
		delete(config, "defaults")
		delete(config, "features")
		delete(config, "default_route_ip")
		delete(config, "primary_gateway_ip")
		delete(config, "secondary_gateway_ip")
		delete(config, "network_id")
		delete(config, "nodes")
		delete(config, "last_state")
	} else {
		remotedesktopInstalled := true
		disabledFeatures, ok := config["disabled_features"].(*protocol.FeatureListResponse)
		if ok {
			for _, v := range disabledFeatures.Features {
				if v.Name == "remotedesktop" {
					remotedesktopInstalled = false
					break
				}
			}
		}
		if !remotedesktopInstalled {
			remotedesktopInstalled = false
			installedFeatures, ok := config["installed_features"].(*protocol.FeatureListResponse)
			if ok {
				for _, v := range installedFeatures.Features {
					if v.Name == "remotedesktop" {
						remotedesktopInstalled = true
						break
					}
				}
			}
		}
		if remotedesktopInstalled {
			nodes := config["nodes"].(map[string][]*protocol.Host)
			masters := nodes["masters"]
			if len(masters) > 0 {
				urls := make(map[string]string, len(masters))
				endpointIP := config["endpoint_ip"].(string)
				for _, v := range masters {
					urls[v.Name] = fmt.Sprintf("https://%s/_platform/remotedesktop/%s/", endpointIP, v.Name)
				}
				config["remote_desktop"] = urls
			} else {
				remotedesktopInstalled = false
			}
		} else {
			config["remote_desktop"] = fmt.Sprintf("no remote desktop available; to install on all masters, run 'safescale cluster feature add %s remotedesktop'", config["name"].(string))
		}
	}
	return config
}

// clusterInspectCmd handles 'deploy cluster <clustername> inspect'
var clusterInspectCommand = &cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show", "get"},
	Usage:     "inspect CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())

		if err := extractClusterName(c); err != nil {
			return clitools.FailureResponse(err)
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		cluster, err := clientSession.Cluster.Inspect(clusterName, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.RPC, err.Error()))
		}
		clusterConfig, err := outputClusterConfig(cluster)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}
		return clitools.SuccessResponse(clusterConfig)
	},
}

func extractClusterName(c *cli.Context) error {
	if c.NArg() < 1 {
		_ = cli.ShowSubcommandHelp(c)
		return clitools.ExitOnInvalidArgument("Missing mandatory argument CLUSTERNAME.")
	}
	if clusterName = c.Args().First(); clusterName == "" {
		_ = cli.ShowSubcommandHelp(c)
		return clitools.ExitOnInvalidArgument("Invalid argument CLUSTERNAME.")
	}

	return nil
}

// outputClusterConfig displays cluster configuration after filtering and completing some fields
func outputClusterConfig(cluster *protocol.ClusterResponse) (map[string]interface{}, fail.Error) {
	toFormat, xerr := convertToMap(cluster)
	if xerr != nil {
		return nil, xerr
	}

	formatted := formatClusterConfig(toFormat, true)
	return formatted, nil
}

// convertToMap converts clusterInstance to its equivalent in map[string]interface{},
// with fields converted to string and used as keys
func convertToMap(c *protocol.ClusterResponse) (map[string]interface{}, fail.Error) {
	// identity := c.Identity(concurrency.RootTask()

	result := map[string]interface{}{
		"name":             c.GetIdentity().GetName(),
		"flavor":           c.GetIdentity().GetFlavor(),
		"flavor_label":     clusterflavor.Enum(c.GetIdentity().GetFlavor()).String(),
		"complexity":       c.GetIdentity().GetComplexity(),
		"complexity_label": clustercomplexity.Enum(c.GetIdentity().GetComplexity()).String(),
		"admin_login":      "cladm",
		"admin_password":   c.GetIdentity().GetAdminPassword(),
		// "keypair":        c.GetIdentity().GetSshConfig().GetPrivateKey(),
		// "ssh_private_key": c.GetIdentity().GetPrivateKey(),
	}

	if c.Composite != nil && len(c.Composite.Tenants) > 0 {
		result["tenants"] = strings.Join(c.Composite.Tenants, ", ")
	}

	if c.Controlplane != nil {
		if c.Controlplane.Vip != nil {
			result["controlplane_vip"] = c.Controlplane.Vip.PrivateIp
		}
	}

	var sgwpubip string
	if c.Network != nil {
		result["network_id"] = c.Network.NetworkId
		result["cidr"] = c.Network.Cidr
		result["default_route_ip"] = c.Network.DefaultRouteIp
		result["primary_gateway_ip"] = c.Network.GatewayIp
		result["endpoint_ip"] = c.Network.EndpointIp
		result["primary_public_ip"] = c.Network.EndpointIp
		result["secondary_gateway_ip"] = sgwpubip
		if sgwpubip = c.Network.SecondaryPublicIp; sgwpubip != "" {
			result["secondary_public_ip"] = sgwpubip
			result["secondary_gateway_ip"] = c.Network.SecondaryGatewayIp
		}
	}

	if c.Defaults != nil {
		result["defaults"] = map[string]interface{}{
			"image":   c.Defaults.Image,
			"gateway": c.Defaults.GatewaySizing,
			"master":  c.Defaults.MasterSizing,
			"node":    c.Defaults.NodeSizing,
		}
	}

	nodes := map[string][]*protocol.Host{}
	if c.Masters != nil {
		nodes["masters"] = c.Masters
	}
	if c.Nodes != nil {
		nodes["nodes"] = c.Nodes
	}
	result["nodes"] = nodes

	if c.InstalledFeatures != nil {
		result["installed_features"] = c.InstalledFeatures
	}
	if c.DisabledFeatures != nil {
		result["disabled_features"] = c.DisabledFeatures
	}

	result["last_state"] = c.State
	result["admin_login"] = "cladm"

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
			Usage: `Defines the sizing of the cluster: Small, Normal, Large
	Default number of machines (#master, #nodes) depending of flavor are:
		BOH: Small(1,1), Normal(3,3), Large(5,6)
		K8S: Small(1,1), Normal(3,3), Large(5,6)
	`,
		},
		&cli.StringFlag{
			Name:    "flavor",
			Aliases: []string{"F"},
			Value:   "K8S",
			Usage: `Defines the type of the cluster; can be BOH, SWARM, OHPC, DCOS, K8S
	Default sizing for each cluster type is:
		BOH: gws(cpu=[2-4], ram=[7-16], disk=[50]), masters(cpu=[4-8], ram=[15-32], disk=[100]), nodes(cpu=[2-4], ram=[15-32], disk=[80])
		K8S: gws(cpu=[2-4], ram=[7-16], disk=[50]), masters(cpu=[4-8], ram=[15-32], disk=[100]), nodes(cpu=[4-8], ram=[15-32], disk=[80])
	`,
		},
		&cli.BoolFlag{
			Name:    "keep-on-failure",
			Aliases: []string{"k"},
			Usage:   "If used, the resources are not deleted on failure (default: not set)",
		},
		&cli.BoolFlag{
			Name:  "force, f",
			Usage: "If used, it forces the cluster creation even if requested sizing is less than recommended",
		},
		&cli.StringFlag{
			Name:    "cidr",
			Aliases: []string{"N"},
			Value:   stacks.DefaultNetworkCIDR,
			Usage:   "Defines the CIDR of the network to use with cluster",
		},
		&cli.StringFlag{
			Name:  "domain",
			Value: "cluster.local",
			Usage: "domain name of the hosts in the cluster (default: cluster.local)",
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
	<component> can be cpu, cpufreq, gpu, ram, disk, template (the latter takes precedence over the formers, but corrupting the cloud-agnostic principle)
	<operator> can be =,~,<,<=,>,>= (except for disk where valid operators are only = or >=):
		- = means exactly <value> (only operator allowed for template)
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
		- <template> is expecting the name of a template from Cloud Provider; if template is not found, fallback to other components defined
	examples:
		--sizing "cpu <= 4, ram <= 10, disk = 100"
		--sizing "cpu ~ 4, ram = [14-32]" (is identical to --sizing "cpu=[4-8], ram=[14-32]")
		--sizing "cpu <= 8, ram ~ 16"
		--sizing "template=x1.large"
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
			Name: "node-sizing",
			Usage: `Describe node sizing in format "<component><operator><value>[,...]" (cf. --sizing for details),
		This parameter accepts a supplemental <component> named count, with only = as <operator> and an int as <value> corresponding to the
		number of workers to create (cannot be less than the minimum required by the flavour).
	example:
		--node-sizing "cpu~4, ram~15, count=8" will create 8 nodes`,
		},
	},

	Action: func(c *cli.Context) (err error) {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())

		if err = extractClusterName(c); err != nil {
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

		force := c.Bool("force")
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

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

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
			Force:         force,
			// NodeCount:     uint32(c.Int("initial-node-count")),
		}
		res, err := clientSession.Cluster.Create(&req, temporal.GetLongOperationTimeout())

		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}
		if res == nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, "failed to create cluster: unknown reason"))
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
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
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

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err = clientSession.Cluster.Delete(clusterName, force, temporal.GetLongOperationTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
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
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err = clientSession.Cluster.Stop(clusterName, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
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
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		clusterRef := c.Args().First()

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		if err = clientSession.Cluster.Start(clusterRef, temporal.GetExecutionTimeout()); err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "start of cluster", false).Error())))
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
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		state, err := clientSession.Cluster.GetState(clusterName, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
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
		&cli.BoolFlag{
			Name:    "keep-on-failure",
			Aliases: []string{"k"},
			Usage:   `do not delete resources on failure`,
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		count := c.Uint("count")
		if count == 0 {
			count = 1
		}
		los := c.String("os")
		keepOnFailure := c.Bool("keep-on-failure")

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
			Name:          clusterName,
			Count:         int32(count),
			NodeSizing:    nodesDef,
			ImageId:       los,
			KeepOnFailure: keepOnFailure,
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		hosts, err := clientSession.Cluster.Expand(&req, temporal.GetLongOperationTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
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
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		count := c.Uint("count")
		yes := c.Bool("yes")

		var countS string
		if count > 1 {
			countS = "s"
		}

		if !yes {
			msg := fmt.Sprintf("Are you sure you want to delete %d node%s from Cluster %s", count, countS, clusterName)
			if !utils.UserConfirmed(msg) {
				return clitools.SuccessResponse("Aborted")
			}
		}

		req := protocol.ClusterResizeRequest{
			Name:  clusterName,
			Count: int32(count),
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		if _, err = clientSession.Cluster.Shrink(&req, temporal.GetLongOperationTimeout()); err != nil {
			err = fail.FromGRPCStatus(err)
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
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
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
								Remote: fmt.Sprintf("%s/kubectl_values_%d.%s.%d.tmp", utils.TempFolder, idx+1, clientID, time.Now().UnixNano()),
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

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		return executeCommand(clientSession, cmdStr, valuesOnRemote, outputs.DISPLAY)
	},
}

var clusterHelmCommand = &cli.Command{
	Name:      "helm",
	Category:  "Administrative commands",
	Usage:     "helm CLUSTERNAME COMMAND [[--][PARAMS ...]]",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
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
			case "--help":
				useTLS = ""
			case "init":
				if idx == 0 {
					return cli.NewExitError("helm init is forbidden", int(exitcode.InvalidArgument))
				}
			case "search", "repo", "help", "install", "uninstall":
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

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		return executeCommand(clientSession, cmdStr, valuesOnRemote, outputs.DISPLAY)
	},
}

var clusterRunCommand = &cli.Command{
	Name:      "run",
	Aliases:   []string{"execute", "exec"},
	Usage:     "run CLUSTERNAME COMMAND",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "clusterRunCmd not yet implemented"))
	},
}

func executeCommand(clientSession *client.Session, command string, files *client.RemoteFilesHandler, outs outputs.Enum) error {
	logrus.Debugf("command=[%s]", command)
	master, err := clientSession.Cluster.FindAvailableMaster(clusterName, 0) // FIXME: set duration
	if err != nil {
		msg := fmt.Sprintf("No masters found available for the cluster '%s': %v", clusterName, err.Error())
		return clitools.ExitOnErrorWithMessage(exitcode.RPC, msg)
	}

	if files != nil && files.Count() > 0 {
		if !Debug {
			defer files.Cleanup(clientSession, master.GetId())
		}
		xerr := files.Upload(clientSession, master.GetId())
		if xerr != nil {
			return clitools.ExitOnErrorWithMessage(exitcode.RPC, xerr.Error())
		}
	}

	retcode, _ /*stdout*/, _ /*stderr*/, xerr := clientSession.SSH.Run(master.GetId(), command, outs, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if xerr != nil {
		msg := fmt.Sprintf("failed to execute command on master '%s' of cluster '%s': %s", master.GetName(), clusterName, xerr.Error())
		return clitools.ExitOnErrorWithMessage(exitcode.RPC, msg)
	}
	if retcode != 0 {
		return cli.NewExitError("" /*msg*/, retcode)
	}
	return nil
}

// clusterListFeaturesCommand handles 'safescale cluster <cluster name or id> list-features'
var clusterListFeaturesCommand = &cli.Command{
	Name:      "list-features",
	Aliases:   []string{"list-installed-features"},
	Usage:     "List the features installed on the cluster",
	ArgsUsage: "",

	Flags: []cli.Flag{
		// &cli.StringSliceFlag{
		//	Name:    "param",
		//	Aliases: []string{"p"},
		//	Usage:   "Allow to define content of feature parameters",
		// },
		&cli.BoolFlag{
			Name:    "all",
			Aliases: []string{"a"},
			Usage:   "If used, list all features eligible to be installed on the cluster",
		},
	},

	Action: clusterFeatureListAction,
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

	Action: clusterFeatureAddAction,
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
	Action: clusterFeatureCheckAction,
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
	Action: clusterFeatureRemoveAction,
}

const clusterNodeCmdLabel = "node"

// clusterNodeCommands handles 'safescale cluster node' commands
var clusterNodeCommands = &cli.Command{
	Name:      clusterNodeCmdLabel,
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
	Usage:     "Lists the nodes of a cluster",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		var formatted []map[string]interface{}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		list, err := clientSession.Cluster.ListNodes(clusterName, temporal.GetExecutionTimeout())
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}

		for _, host := range list.Nodes {
			formatted = append(formatted, map[string]interface{}{
				"name": host.GetName(),
				"id":   host.GetId(),
			})
		}
		return clitools.SuccessResponse(formatted)
	},
}

// clusterNodeInspectCmd handles 'deploy cluster <clustername> inspect'
var clusterNodeInspectCommand = &cli.Command{
	Name:      "inspect",
	Usage:     "Show details about a cluster node",
	ArgsUsage: "CLUSTERNAME HOSTNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		host, err := clientSession.Cluster.InspectNode(clusterName, hostName, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
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
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		var nodeList []string
		nodeList = c.Args().Tail()
		yes := c.Bool("yes")
		force := c.Bool("force")

		if !yes && !utils.UserConfirmed(fmt.Sprintf("Are you sure you want to delete the node%s '%s' of the cluster '%s'", strprocess.Plural(uint(len(nodeList))), strings.Join(nodeList, ","), clusterName)) {
			return clitools.SuccessResponse("Aborted")
		}
		if force {
			logrus.Println("'-f,--force' does nothing yet")
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err = clientSession.Cluster.DeleteNode(clusterName, nodeList, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterNodeStopCmd handles 'deploy cluster <clustername> node <nodename> stop'
var clusterNodeStopCommand = &cli.Command{
	Name:      "stop",
	Aliases:   []string{"freeze"},
	Usage:     "node stop CLUSTERNAME HOSTNAME",
	ArgsUsage: "CLUSTERNAME HOSTNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err = clientSession.Cluster.StopNode(clusterName, hostName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterNodeStartCmd handles 'deploy cluster <clustername> node <nodename> start'
var clusterNodeStartCommand = &cli.Command{
	Name:      "start",
	Aliases:   []string{"unfreeze"},
	Usage:     "node start CLUSTERNAME HOSTNAME",
	ArgsUsage: "CLUSTERNAME NODENAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err = clientSession.Cluster.StartNode(clusterName, hostName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterNodeStateCmd handles 'deploy cluster <clustername> state'
var clusterNodeStateCommand = &cli.Command{
	Name:      "state",
	Usage:     "node state CLUSTERNAME HOSTNAME",
	ArgsUsage: "CLUSTERNAME NODENAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		resp, err := clientSession.Cluster.StateNode(clusterName, hostName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}

		formatted := make(map[string]interface{})
		formatted["name"] = resp.Name
		converted := converters.HostStateFromProtocolToEnum(resp.Status)
		formatted["status_code"] = converted
		formatted["status_label"] = converted.String()
		return clitools.SuccessResponse(formatted)
	},
}

const clusterMasterCmdLabel = "master"

// clusterMasterCommands handles 'safescale cluster master ...
var clusterMasterCommands = &cli.Command{
	Name:      clusterMasterCmdLabel,
	Usage:     "manage cluster masters",
	ArgsUsage: "COMMAND",

	Subcommands: []*cli.Command{
		clusterMasterListCommand,
		clusterMasterInspectCommand,
	},
}

// clusterMasterListCommand handles 'safescale cluster master list CLUSTERNAME'
var clusterMasterListCommand = &cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "list CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		var formatted []map[string]interface{}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		list, err := clientSession.Cluster.ListMasters(clusterName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}

		for _, host := range list.Nodes {
			formatted = append(formatted, map[string]interface{}{
				"name": host.GetName(),
				"id":   host.GetId(),
			})
		}
		return clitools.SuccessResponse(formatted)
	},
}

// clusterMasterInspectCmd handles 'cluster master inspect <clustername> <masterref>'
var clusterMasterInspectCommand = &cli.Command{
	Name:      "inspect",
	Usage:     "Show details about a Cluster master",
	ArgsUsage: "CLUSTERNAME MASTERNAME",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		host, err := clientSession.Cluster.InspectNode(clusterName, hostName, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(host)
	},
}

// clusterMasterStopCmd handles 'safescale cluster master stop <clustername> <mastername>'
var clusterMasterStopCommand = &cli.Command{
	Name:      "stop",
	Aliases:   []string{"freeze"},
	Usage:     "master stop CLUSTERNAME MASTERNAME",
	ArgsUsage: "CLUSTERNAME MASTERNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err = clientSession.Cluster.StopMaster(clusterName, hostName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterMasterStartCmd handles 'deploy cluster <clustername> node <nodename> start'
var clusterMasterStartCommand = &cli.Command{
	Name:      "start",
	Aliases:   []string{"unfreeze"},
	Usage:     "master start CLUSTERNAME MASTERNAME",
	ArgsUsage: "CLUSTERNAME MASTERNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err = clientSession.Cluster.StartMaster(clusterName, hostName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterMasterNodeStateCmd handles 'safescale cluster master state <clustername> <mastername>'
var clusterMasterStateCommand = &cli.Command{
	Name:      "state",
	Usage:     "master state CLUSTERNAME MASTERNAME",
	ArgsUsage: "CLUSTERNAME MASTERNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		resp, err := clientSession.Cluster.StateMaster(clusterName, hostName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}

		formatted := make(map[string]interface{})
		formatted["name"] = resp.Name
		converted := converters.HostStateFromProtocolToEnum(resp.Status)
		formatted["status_code"] = converted
		formatted["status_label"] = converted.String()
		return clitools.SuccessResponse(formatted)
	},
}

const clusterFeatureCmdLabel = "feature"

// clusterFeatureCommands commands
var clusterFeatureCommands = &cli.Command{
	Name:      clusterFeatureCmdLabel,
	Usage:     "create and manage features on a cluster",
	ArgsUsage: "COMMAND",
	Subcommands: []*cli.Command{
		clusterFeatureListCommand,
		clusterFeatureCheckCommand,
		clusterFeatureAddCommand,
		clusterFeatureRemoveCommand,
	},
}

// clusterFeatureListCommand handles 'safescale cluster <cluster name or id> list-features'
var clusterFeatureListCommand = &cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "List features installed on the cluster",
	ArgsUsage: "",

	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "all",
			Aliases: []string{"a"},
			Value:   false,
			Usage:   "if used, list all features that are eligible to be installed on the cluster",
		},
		// &cli.StringSliceFlag{
		// 	Name:    "param",
		// 	Aliases: []string{"p"},
		// 	Usage:   "Allow to define content of feature parameters",
		// },
	},

	Action: clusterFeatureListAction,
}

func clusterFeatureListAction(c *cli.Context) error {
	logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())

	clientSession, xerr := client.New(c.String("server"))
	if xerr != nil {
		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
	}

	if err := extractClusterName(c); err != nil {
		return clitools.FailureResponse(err)
	}

	features, err := clientSession.Cluster.ListInstalledFeatures(clusterName, c.Bool("all"), 0) // FIXME: set timeout
	if err != nil {
		err = fail.FromGRPCStatus(err)
		return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
	}

	return clitools.SuccessResponse(features)
}

// clusterFeatureAddCommand handles 'safescale cluster feature add CLUSTERNAME FEATURENAME'
var clusterFeatureAddCommand = &cli.Command{
	Name:      "add",
	Aliases:   []string{"install"},
	Usage:     "Installs a feature on a cluster",
	ArgsUsage: "CLUSTERNAME FEATURENAME",

	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "param",
			Aliases: []string{"p"},
			Usage:   "Define value of feature parameters, in format <name>=<value>",
		},
		&cli.BoolFlag{
			Name:  "skip-proxy",
			Usage: "Disables reverse proxy rules",
		},
	},

	Action: clusterFeatureAddAction,
}

func clusterFeatureAddAction(c *cli.Context) error {
	logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterFeatureCmdLabel, c.Command.Name, c.Args())
	if err := extractClusterName(c); err != nil {
		return clitools.FailureResponse(err)
	}

	if err := extractFeatureArgument(c); err != nil {
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

	clientSession, xerr := client.New(c.String("server"))
	if xerr != nil {
		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
	}

	if err := clientSession.Cluster.AddFeature(clusterName, featureName, values, &settings, 0); err != nil {
		err = fail.FromGRPCStatus(err)
		msg := fmt.Sprintf("error adding feature '%s' on cluster '%s': %s", featureName, clusterName, err.Error())
		return clitools.FailureResponse(clitools.ExitOnRPC(msg))
	}
	return clitools.SuccessResponse(nil)
}

// clusterFeatureCheckCommand handles 'deploy cluster check-feature CLUSTERNAME FEATURENAME'
var clusterFeatureCheckCommand = &cli.Command{
	Name:      "check",
	Aliases:   []string{"verify"},
	Usage:     "Checks if a eature is already installed on cluster",
	ArgsUsage: "CLUSTERNAME FEATURENAME",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "param",
			Aliases: []string{"p"},
			Usage:   "Allow to define content of feature parameters",
		},
	},
	Action: clusterFeatureCheckAction,
}

func clusterFeatureCheckAction(c *cli.Context) error {
	logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterFeatureCmdLabel, c.Command.Name, c.Args())

	if err := extractClusterName(c); err != nil {
		return clitools.FailureResponse(err)
	}

	if err := extractFeatureArgument(c); err != nil {
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

	clientSession, xerr := client.New(c.String("server"))
	if xerr != nil {
		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
	}

	if err := clientSession.Cluster.CheckFeature(clusterName, featureName, values, &settings, 0); err != nil { // FIXME: define duration
		err = fail.FromGRPCStatus(err)
		msg := fmt.Sprintf("error checking Feature '%s' on Cluster '%s': %s", featureName, clusterName, err.Error())
		return clitools.FailureResponse(clitools.ExitOnRPC(msg))
	}

	msg := fmt.Sprintf("Feature '%s' found on cluster '%s'", featureName, clusterName)
	return clitools.SuccessResponse(msg)
}

// clusterFeatureRemoveCommand handles 'safescale cluster feature remove <cluster name> <pkgname>'
var clusterFeatureRemoveCommand = &cli.Command{
	Name:      "remove",
	Aliases:   []string{"destroy", "delete", "rm", "uninstall"},
	Usage:     "Remove a feature from a cluster",
	ArgsUsage: "CLUSTERNAME FEATURENAME",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "param",
			Aliases: []string{"p"},
			Usage:   "Allow to define content of feature parameters",
		},
	},
	Action: clusterFeatureRemoveAction,
}

func clusterFeatureRemoveAction(c *cli.Context) error {
	logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterFeatureCmdLabel, c.Command.Name, c.Args())
	if err := extractClusterName(c); err != nil {
		return clitools.FailureResponse(err)
	}

	if err := extractFeatureArgument(c); err != nil {
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

	clientSession, xerr := client.New(c.String("server"))
	if xerr != nil {
		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
	}

	if err := clientSession.Cluster.RemoveFeature(clusterName, featureName, values, &settings, 0); err != nil {
		err = fail.FromGRPCStatus(err)
		msg := fmt.Sprintf("failed to remove Feature '%s' on Cluster '%s': %s", featureName, clusterName, err.Error())
		return clitools.FailureResponse(clitools.ExitOnRPC(msg))
	}
	return clitools.SuccessResponse(nil)
}
