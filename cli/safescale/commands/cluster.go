/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"archive/zip"
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/schollz/progressbar/v3"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/client"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

var (
	clusterName string
)

const clusterCmdLabel = "cluster"

// ClusterCommand command
var ClusterCommand = cli.Command{
	Name:      "cluster",
	Aliases:   []string{"datacenter", "dc", "platform"},
	Usage:     "create and manage cluster",
	ArgsUsage: "COMMAND",
	Subcommands: cli.Commands{
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
		clusterAnsibleCommands,
		clusterListFeaturesCommand,
		clusterCheckFeatureCommand,
		clusterAddFeatureCommand,
		clusterRemoveFeatureCommand,
		clusterFeatureCommands,
	},
}

// clusterListCommand handles 'deploy cluster list'
var clusterListCommand = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available clusters",

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Listing clusters"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		list, err := ClientSession.Cluster.List(0)
		if err != nil {
			err := fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "failed to get cluster list", false).Error())))
		}

		var formatted []interface{}
		for _, value := range list.Clusters {
			// c, _ := value.(api.Cluster)
			converted, err := convertToMap(value)
			if err != nil {
				debug.IgnoreError(err)
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, fmt.Sprintf("failed to extract data about cluster '%s'", clusterName)))
			}

			fconfig, err := formatClusterConfig(converted, false)
			if err != nil {
				debug.IgnoreError(err)
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, fmt.Sprintf("failed to extract data about cluster '%s'", clusterName)))
			}
			formatted = append(formatted, fconfig)
		}
		return clitools.SuccessResponse(formatted)
	},
}

// formatClusterConfig removes unneeded entry from config
func formatClusterConfig(config map[string]interface{}, detailed bool) (map[string]interface{}, fail.Error) {
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
		delete(config, "last_state_label")
	} else {
		// FIXME: There is no actual check for features, the check is implicit, this is wrong, ALL checks MUST be EXPLICIT
		remotedesktopInstalled := false
		disabledFeatures, ok := config["disabled_features"].(*protocol.FeatureListResponse)
		if ok {
			for _, v := range disabledFeatures.Features {
				if v.Name == "docker" {
					remotedesktopInstalled = false
					break
				}
				if v.Name == "remotedesktop" {
					remotedesktopInstalled = false
					break
				}
			}
		}
		if !remotedesktopInstalled {
			remotedesktopInstalled = false
			installedFeatures, ok := config["installed_features"].(*protocol.FeatureListResponse)
			if !ok {
				return nil, fail.InconsistentError("'installed_features' should be a *protocol.FeatureListResponse")
			}
			for _, v := range installedFeatures.Features {
				if v.Name == "remotedesktop" {
					remotedesktopInstalled = true
					break
				}
			}
		}
		if remotedesktopInstalled {
			nodes, ok := config["nodes"].(map[string][]*protocol.Host)
			if ok {
				masters := nodes["masters"]
				if len(masters) > 0 {
					urls := make(map[string]string, len(masters))
					endpointIP, ok := config["endpoint_ip"].(string)
					if ok {
						for _, v := range masters {
							urls[v.Name] = fmt.Sprintf("https://%s/_platform/remotedesktop/%s/", endpointIP, v.Name)
						}
						config["remote_desktop"] = urls
					} else {
						return nil, fail.InconsistentError("'endpoint_ip' should be a string")
					}
				}
			} else {
				return nil, fail.InconsistentError("'nodes' should be a map[string][]*protocol.Host")
			}
		} else {
			config["remote_desktop"] = fmt.Sprintf("no remote desktop available; to install on all masters, run 'safescale cluster feature add %s remotedesktop'", config["name"].(string))
		}
	}
	return config, nil
}

// clusterInspectCmd handles 'deploy cluster <clustername> inspect'
var clusterInspectCommand = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show", "get"},
	Usage:     "inspect CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())

		if err := extractClusterName(c); err != nil {
			return clitools.FailureResponse(err)
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Inspecting cluster"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		cluster, err := ClientSession.Cluster.Inspect(clusterName, 0)
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

func extractClusterName(c *cli.Context) (ferr error) {
	defer fail.OnPanic(&ferr)
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

	formatted, err := formatClusterConfig(toFormat, true)
	if err != nil {
		return nil, err
	}
	return formatted, err
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
		result["subnet_id"] = c.Network.SubnetId
		result["cidr"] = c.Network.Cidr
		result["default_route_ip"] = c.Network.DefaultRouteIp
		result["primary_gateway_ip"] = c.Network.GatewayIp
		result["endpoint_ip"] = c.Network.EndpointIp
		result["primary_public_ip"] = c.Network.EndpointIp
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
	result["last_state_label"] = c.State.String()
	result["admin_login"] = "cladm"

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
			Usage: `Defines the sizing of the cluster: Small, Normal, Large
	Default number of machines (#master, #nodes) depending of flavor are:
		BOH: Small(1,1), Normal(3,3), Large(5,6)
		K8S: Small(1,1), Normal(3,3), Large(5,6)
	`,
		},
		cli.StringFlag{
			Name:  "flavor, F",
			Value: "K8S",
			Usage: `Defines the type of the cluster; can be BOH, K8S
	Default sizing for each cluster type is:
		BOH: gws(cpu=[2-4], ram=[7-16], disk=[50]), masters(cpu=[4-8], ram=[15-32], disk=[100]), nodes(cpu=[2-4], ram=[15-32], disk=[80])
		K8S: gws(cpu=[2-4], ram=[7-16], disk=[50]), masters(cpu=[4-8], ram=[15-32], disk=[100]), nodes(cpu=[4-8], ram=[15-32], disk=[80])
	`,
		},
		cli.BoolFlag{
			Name:  "keep-on-failure, k",
			Usage: "If used, the resources are not deleted on failure (default: not set)",
		},
		cli.BoolFlag{
			Name:  "force, f",
			Usage: "If used, it forces the cluster creation even if requested sizing is less than recommended",
		},
		cli.IntFlag{
			Name:  "gwport, default-ssh-port",
			Value: 22,
			Usage: `Define the port to use for SSH (default: 22) in gateways`,
		},
		cli.StringFlag{
			Name:  "cidr, N",
			Value: stacks.DefaultNetworkCIDR,
			Usage: "Defines the CIDR of the network to use with cluster",
		},
		cli.StringFlag{
			Name:  "domain",
			Value: "cluster.local",
			Usage: "domain name of the hosts in the cluster (default: cluster.local)",
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
		cli.StringFlag{
			Name:  "gw-sizing",
			Usage: `Describe gateway sizing in format "<component><operator><value>[,...] (cf. --sizing for details)`,
		},
		cli.StringFlag{
			Name:  "master-sizing",
			Usage: `Describe master sizing in format "<component><operator><value>[,...]" (cf. --sizing for details)`,
		},
		cli.StringFlag{
			Name: "node-sizing",
			Usage: `Describe node sizing in format "<component><operator><value>[,...]" (cf. --sizing for details),
		This parameter accepts a supplemental <component> named count, with only = as <operator> and an int as <value> corresponding to the
		number of workers to create (cannot be less than the minimum required by the flavor).
	example:
		--node-sizing "cpu~4, ram~15, count=8" will create 8 nodes`,
		},
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define parameter values for automatically installed Features (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
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
		gatewaySSHPort := uint32(c.Int("gwport"))

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
			if strings.Contains(c.String("master-sizing"), "count") {
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("the number of masters cannot be changed yet: count cannot be included in 'master-sizing' flag"))
			}

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

		req := protocol.ClusterCreateRequest{
			Name:           clusterName,
			Complexity:     protocol.ClusterComplexity(comp),
			Flavor:         protocol.ClusterFlavor(fla),
			KeepOnFailure:  keep,
			Cidr:           cidr,
			Disabled:       disable,
			Os:             los,
			GlobalSizing:   globalDef,
			GatewaySizing:  gatewaysDef,
			MasterSizing:   mastersDef,
			NodeSizing:     nodesDef,
			Force:          force,
			Parameters:     c.StringSlice("param"),
			DefaultSshPort: gatewaySSHPort,
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Creating cluster"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		res, err := ClientSession.Cluster.Create(&req, 0)

		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}
		if res == nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, "failed to create cluster: unknown reason"))
		}

		toFormat, cerr := convertToMap(res)
		if cerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, cerr.Error()))
		}

		formatted, cerr := formatClusterConfig(toFormat, true)
		if cerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, cerr.Error()))
		}

		delete(formatted, "defaults")
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

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
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

		err = ClientSession.Cluster.Delete(clusterName, force, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
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

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = ClientSession.Cluster.Stop(clusterName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
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

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}
		clusterRef := c.Args().First()

		if err = ClientSession.Cluster.Start(clusterRef, 0); err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "start of cluster", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterStateCmd handles 'deploy cluster <clustername> state'
var clusterStateCommand = cli.Command{
	Name:      "state",
	Usage:     "state CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Getting cluster state"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		state, err := ClientSession.Cluster.GetState(clusterName, 0)
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
		cli.StringFlag{
			Name: "node-sizing",
			Usage: `Describe node sizing in format "<component><operator><value>[,...]" where:
	<component> can be cpu, cpufreq, gpu, ram, disk, os
	<operator> can be =,<,> (except for disk where valid operators are only = or >)
	<value> can be an integer (for cpu and disk) or a float (for ram) or an including interval "[<lower value>-<upper value>]"`,
		},
		cli.BoolFlag{
			Name:  "keep-on-failure, k",
			Usage: `do not delete resources on failure`,
		},
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define parameter values for automatically installed Features (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
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
			Parameters:    c.StringSlice("param"),
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Expanding cluster"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		hosts, err := ClientSession.Cluster.Expand(&req, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
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

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
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

		if _, err = ClientSession.Cluster.Shrink(&req, 0); err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

var clusterKubectlCommand = cli.Command{
	Name:      "kubectl",
	Category:  "Administrative commands",
	Usage:     "kubectl CLUSTERNAME [KUBECTL_COMMAND]... [-- [KUBECTL_OPTIONS]...]",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
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
						// If it's a URL, propagate as-is
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

		clientSession, xerr := client.New(c.String("server"), c.String("tenant"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err = executeCommand(clientSession, cmdStr, valuesOnRemote, outputs.DISPLAY)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}

		return clitools.SuccessResponse(nil)
	},
}

var clusterHelmCommand = cli.Command{
	Name:      "helm",
	Category:  "Administrative commands",
	Usage:     "helm CLUSTERNAME COMMAND [[--][PARAMS ...]]",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		clientID := GenerateClientIdentity()
		// useTLS := " --tls"
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
			// case "--help":
			//	useTLS = ""
			case "init":
				if idx == 0 {
					return cli.NewExitError("helm init is forbidden", int(exitcode.InvalidArgument))
				}
			// case "search", "repo", "help", "install", "uninstall":
			//	if idx == 0 {
			//		useTLS = ""
			//	}
			case "--":
				ignore = true
			case "-f", "--values":
				if idx+1 < len(args) {
					localFile := args[idx+1]
					if localFile != "" {
						// If it's a URL, filter as-is
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
		cmdStr := `sudo -u cladm -i helm ` + strings.Join(filteredArgs, " ") // + useTLS

		clientSession, xerr := client.New(c.String("server"), c.String("tenant"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err = executeCommand(clientSession, cmdStr, valuesOnRemote, outputs.DISPLAY)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}

		return clitools.SuccessResponse(nil)
	},
}

var clusterRunCommand = cli.Command{
	Name:      "run",
	Aliases:   []string{"execute", "exec"},
	Usage:     "run CLUSTERNAME COMMAND",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
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

	master, err := ClientSession.Cluster.FindAvailableMaster(clusterName, 0) // FIXME: set duration
	if err != nil {
		return fmt.Errorf("no masters found available for the cluster '%s': %w", clusterName, err)
	}

	if files != nil && files.Count() > 0 {
		defer files.Cleanup(clientSession, master.GetId())
		xerr := files.Upload(clientSession, master.GetId())
		if xerr != nil {
			return xerr
		}
	}

	retcode, _, _, xerr := clientSession.SSH.Run(master.GetId(), command, outs, temporal.ConnectionTimeout(), 0)
	if xerr != nil {
		return fmt.Errorf("failed to execute command on master '%s' of cluster '%s': %w", master.GetName(), clusterName, xerr)
	}
	if retcode != 0 {
		return cli.NewExitError("" /*msg*/, retcode)
	}
	return nil
}

// clusterListFeaturesCommand handles 'safescale cluster <cluster name or id> list-features'
var clusterListFeaturesCommand = cli.Command{
	Name:      "list-features",
	Aliases:   []string{"list-installed-features"},
	Usage:     "List the features installed on the cluster",
	ArgsUsage: "",

	Flags: []cli.Flag{
		// cli.StringSliceFlag{
		//	Name:    "param",
		//	Aliases: []string{"p"},
		//	Usage:   "Allow to define content of feature parameters",
		// },
		cli.BoolFlag{
			Name:  "all, a",
			Usage: "If used, list all features eligible to be installed on the cluster",
		},
	},

	Action: clusterFeatureListAction,
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
			Usage: "Allow to define content of Feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
		},
		cli.BoolFlag{
			Name:  "skip-proxy",
			Usage: "Disables reverse proxy rules",
		},
	},

	Action: clusterFeatureAddAction,
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
			Usage: "Allow to define content of feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
		},
	},
	Action: clusterFeatureCheckAction,
}

// clusterRemoveFeatureCommand handles 'deploy host <host name or id> package <pkgname> delete'
var clusterRemoveFeatureCommand = cli.Command{
	Name:      "remove-feature",
	Aliases:   []string{"destroy-feature", "delete-feature", "rm-feature", "uninstall-feature"},
	Usage:     "delete-feature CLUSTERNAME FEATURENAME",
	ArgsUsage: "CLUSTERNAME FEATURENAME",
	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
		},
	},
	Action: clusterFeatureRemoveAction,
}

const clusterNodeCmdLabel = "node"

// clusterNodeCommands handles 'safescale cluster node' commands
var clusterNodeCommands = cli.Command{
	Name:      clusterNodeCmdLabel,
	Usage:     "manage cluster nodes",
	ArgsUsage: "COMMAND",

	Subcommands: cli.Commands{
		clusterNodeListCommand,
		clusterNodeInspectCommand,
		clusterNodeStartCommand,
		clusterNodeStopCommand,
		clusterNodeStateCommand,
		clusterNodeDeleteCommand,
	},
}

// clusterNodeListCommand handles 'deploy cluster node list CLUSTERNAME'
var clusterNodeListCommand = cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "Lists the nodes of a cluster",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		var formatted []map[string]interface{}

		beta := os.Getenv("SAFESCALE_BETA")
		if beta != "" {
			pb := progressbar.Default(-1, "Listing cluster nodes")
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Listing cluster nodes"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		list, err := ClientSession.Cluster.ListNodes(clusterName, 0)
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
var clusterNodeInspectCommand = cli.Command{
	Name:      "inspect",
	Usage:     "Show details about a cluster node",
	ArgsUsage: "CLUSTERNAME HOSTNAME",

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		hostName, err := extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Inspecting cluster node"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		host, err := ClientSession.Cluster.InspectNode(clusterName, hostName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(host)
	},
}

// clusterNodeDeleteCmd handles 'deploy cluster <clustername> delete'
var clusterNodeDeleteCommand = cli.Command{
	Name:    "delete",
	Aliases: []string{"destroy", "remove", "rm"},

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "yes, y",
			Usage: "If set, respond automatically yes to all questions",
		},
		cli.BoolFlag{
			Name:  "force, f",
			Usage: "If set, force node deletion no matter what (ie. metadata inconsistency)",
		},
	},

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		nodeList := c.Args().Tail()
		yes := c.Bool("yes")
		force := c.Bool("force")

		_, err = ClientSession.Cluster.Inspect(clusterName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.RPC, err.Error()))
		}

		if len(nodeList) == 0 {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.InvalidArgument, "missing nodes"))
		}

		if !yes && !utils.UserConfirmed(fmt.Sprintf("Are you sure you want to delete the node%s '%s' of the cluster '%s'", strprocess.Plural(uint(len(nodeList))), strings.Join(nodeList, ","), clusterName)) {
			return clitools.SuccessResponse("Aborted")
		}
		if force {
			logrus.Println("'-f,--force' does nothing yet")
		}

		err = ClientSession.Cluster.DeleteNode(clusterName, nodeList, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterNodeStopCmd handles 'deploy cluster <clustername> node <nodename> stop'
var clusterNodeStopCommand = cli.Command{
	Name:      "stop",
	Aliases:   []string{"freeze"},
	Usage:     "node stop CLUSTERNAME HOSTNAME",
	ArgsUsage: "CLUSTERNAME HOSTNAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		hostName, err := extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = ClientSession.Cluster.StopNode(clusterName, hostName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterNodeStartCmd handles 'deploy cluster <clustername> node <nodename> start'
var clusterNodeStartCommand = cli.Command{
	Name:      "start",
	Aliases:   []string{"unfreeze"},
	Usage:     "node start CLUSTERNAME HOSTNAME",
	ArgsUsage: "CLUSTERNAME NODENAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		hostName, err := extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = ClientSession.Cluster.StartNode(clusterName, hostName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterNodeStateCmd handles 'deploy cluster <clustername> state'
var clusterNodeStateCommand = cli.Command{
	Name:      "state",
	Usage:     "node state CLUSTERNAME HOSTNAME",
	ArgsUsage: "CLUSTERNAME NODENAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		hostName, err := extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Getting node state"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		resp, err := ClientSession.Cluster.StateNode(clusterName, hostName, 0)
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
var clusterMasterCommands = cli.Command{
	Name:      clusterMasterCmdLabel,
	Usage:     "manage cluster masters",
	ArgsUsage: "COMMAND",

	Subcommands: cli.Commands{
		clusterMasterListCommand,
		clusterMasterInspectCommand,
		clusterMasterStartCommand,
		clusterMasterStopCommand,
		clusterMasterStateCommand,
	},
}

// clusterMasterListCommand handles 'safescale cluster master list CLUSTERNAME'
var clusterMasterListCommand = cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "list CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		var formatted []map[string]interface{}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Listing masters"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		list, err := ClientSession.Cluster.ListMasters(clusterName, 0)
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
var clusterMasterInspectCommand = cli.Command{
	Name:      "inspect",
	Usage:     "Show details about a Cluster master",
	ArgsUsage: "CLUSTERNAME MASTERNAME",

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		hostName, err := extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Inspecting nodes"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		host, err := ClientSession.Cluster.InspectNode(clusterName, hostName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(host)
	},
}

// clusterMasterStopCmd handles 'safescale cluster master stop <clustername> <mastername>'
var clusterMasterStopCommand = cli.Command{
	Name:      "stop",
	Aliases:   []string{"freeze"},
	Usage:     "master stop CLUSTERNAME MASTERNAME",
	ArgsUsage: "CLUSTERNAME MASTERNAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		hostName, err := extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = ClientSession.Cluster.StopMaster(clusterName, hostName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterMasterStartCmd handles 'deploy cluster <clustername> node <nodename> start'
var clusterMasterStartCommand = cli.Command{
	Name:      "start",
	Aliases:   []string{"unfreeze"},
	Usage:     "master start CLUSTERNAME MASTERNAME",
	ArgsUsage: "CLUSTERNAME MASTERNAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		hostName, err := extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = ClientSession.Cluster.StartMaster(clusterName, hostName, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

// clusterMasterNodeStateCmd handles 'safescale cluster master state <clustername> <mastername>'
var clusterMasterStateCommand = cli.Command{
	Name:      "state",
	Usage:     "master state CLUSTERNAME MASTERNAME",
	ArgsUsage: "CLUSTERNAME MASTERNAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		hostName, err := extractNodeArgument(c, 1)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Checking master state"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		resp, err := ClientSession.Cluster.StateMaster(clusterName, hostName, 0)
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
var clusterFeatureCommands = cli.Command{
	Name:      clusterFeatureCmdLabel,
	Usage:     "create and manage features on a cluster",
	ArgsUsage: "COMMAND",
	Subcommands: cli.Commands{
		clusterFeatureListCommand,
		clusterFeatureInspectCommand,
		clusterFeatureExportCommand,
		clusterFeatureCheckCommand,
		clusterFeatureAddCommand,
		clusterFeatureRemoveCommand,
	},
}

// clusterFeatureListCommand handles 'safescale cluster feature list <cluster name or id>'
var clusterFeatureListCommand = cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "List features installed on the cluster",
	ArgsUsage: "",

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "all, a",
			// Value:   false,
			Usage: "if used, list all features that are eligible to be installed on the cluster",
		},
	},

	Action: clusterFeatureListAction,
}

func clusterFeatureListAction(c *cli.Context) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())

	if err := extractClusterName(c); err != nil {
		return clitools.FailureResponse(err)
	}

	if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
		description := "Listing features"
		pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
		go func() {
			for {
				if pb.IsFinished() {
					return
				}
				err := pb.Add(1)
				if err != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()

		defer func() {
			_ = pb.Finish()
		}()
	}

	features, err := ClientSession.Cluster.ListFeatures(clusterName, c.Bool("all"), 0) // FIXME: set timeout
	if err != nil {
		err = fail.FromGRPCStatus(err)
		return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
	}

	return clitools.SuccessResponse(features)
}

// clusterFeatureInspectCommand handles 'safescale cluster feature inspect <cluster name or id> <feature name>'
// Displays information about the feature (parameters, if eligible on cluster, if installed, ...)
var clusterFeatureInspectCommand = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Inspects the feature",
	ArgsUsage: "",

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "embedded",
			// Value: false,
			Usage: "if used, tells to show details of embedded feature (if it exists)",
		},
	},

	Action: clusterFeatureInspectAction,
}

func clusterFeatureInspectAction(c *cli.Context) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())

	if err := extractClusterName(c); err != nil {
		return clitools.FailureResponse(err)
	}

	featureName, err := extractFeatureArgument(c)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
		description := "Inspecting features"
		pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
		go func() {
			for {
				if pb.IsFinished() {
					return
				}
				err := pb.Add(1)
				if err != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()

		defer func() {
			_ = pb.Finish()
		}()
	}

	details, err := ClientSession.Cluster.InspectFeature(clusterName, featureName, c.Bool("embedded"), 0) // FIXME: set timeout
	if err != nil {
		err = fail.FromGRPCStatus(err)
		return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
	}

	return clitools.SuccessResponse(details)
}

// clusterFeatureExportCommand handles 'safescale cluster feature export <cluster name or id> <feature name>'
var clusterFeatureExportCommand = cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "List features installed on the cluster",
	ArgsUsage: "",

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "embedded",
			// Value: false,
			Usage: "if used, tells to export embedded feature (if it exists)",
		},
		cli.BoolFlag{
			Name: "raw",
			// Value: false,
			Usage: "outputs only the feature content, without json",
		},
	},

	Action: clusterFeatureExportAction,
}

func clusterFeatureExportAction(c *cli.Context) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())

	if err := extractClusterName(c); err != nil {
		return clitools.FailureResponse(err)
	}

	featureName := c.Args().Get(1)
	if featureName == "" {
		_ = cli.ShowSubcommandHelp(c)
		return clitools.ExitOnInvalidArgument("Invalid argument FEATURENAME.")
	}

	if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
		description := "Exporting feature"
		pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
		go func() {
			for {
				if pb.IsFinished() {
					return
				}
				err := pb.Add(1)
				if err != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()

		defer func() {
			_ = pb.Finish()
		}()
	}

	export, err := ClientSession.Cluster.ExportFeature(clusterName, featureName, c.Bool("embedded"), 0) // FIXME: set timeout
	if err != nil {
		err = fail.FromGRPCStatus(err)
		return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
	}

	if c.Bool("raw") {
		return clitools.SuccessResponse(export.Export)
	}

	return clitools.SuccessResponse(export)
}

// clusterFeatureAddCommand handles 'safescale cluster feature add CLUSTERNAME FEATURENAME'
var clusterFeatureAddCommand = cli.Command{
	Name:      "add",
	Aliases:   []string{"install"},
	Usage:     "Installs a feature on a cluster",
	ArgsUsage: "CLUSTERNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Define value of feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
		},
		cli.BoolFlag{
			Name:  "skip-proxy",
			Usage: "Disables reverse proxy rules",
		},
	},

	Action: clusterFeatureAddAction,
}

func clusterFeatureAddAction(c *cli.Context) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterFeatureCmdLabel, c.Command.Name, c.Args())
	if err := extractClusterName(c); err != nil {
		return clitools.FailureResponse(err)
	}

	featureName, err := extractFeatureArgument(c)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	values := parametersToMap(c.StringSlice("param"))
	settings := protocol.FeatureSettings{}
	settings.SkipProxy = c.Bool("skip-proxy")

	if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
		description := "Adding feature"
		pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
		go func() {
			for {
				if pb.IsFinished() {
					return
				}
				err := pb.Add(1)
				if err != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()

		defer func() {
			_ = pb.Finish()
		}()
	}

	if err := ClientSession.Cluster.AddFeature(clusterName, featureName, values, &settings, 0); err != nil {
		err = fail.FromGRPCStatus(err)
		msg := fmt.Sprintf("error adding feature '%s' on cluster '%s': %s", featureName, clusterName, err.Error())
		return clitools.FailureResponse(clitools.ExitOnRPC(msg))
	}
	return clitools.SuccessResponse(nil)
}

// parametersToMap transforms parameters slice to map
func parametersToMap(params []string) map[string]string {
	values := map[string]string{}
	for _, k := range params {
		res := strings.Split(k, "=")
		if len(res[0]) > 0 {
			values[res[0]] = strings.Join(res[1:], "=")
		}
	}
	return values
}

// clusterFeatureCheckCommand handles 'deploy cluster check-feature CLUSTERNAME FEATURENAME'
var clusterFeatureCheckCommand = cli.Command{
	Name:      "check",
	Aliases:   []string{"verify"},
	Usage:     "Checks if a Feature is already installed on cluster",
	ArgsUsage: "CLUSTERNAME FEATURENAME",
	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
		},
	},
	Action: clusterFeatureCheckAction,
}

func clusterFeatureCheckAction(c *cli.Context) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterFeatureCmdLabel, c.Command.Name, c.Args())

	if err := extractClusterName(c); err != nil {
		return clitools.FailureResponse(err)
	}

	featureName, err := extractFeatureArgument(c)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	values := parametersToMap(c.StringSlice("param"))
	settings := protocol.FeatureSettings{}

	if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
		description := "Checking cluster feature"
		pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
		go func() {
			for {
				if pb.IsFinished() {
					return
				}
				err := pb.Add(1)
				if err != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()

		defer func() {
			_ = pb.Finish()
		}()
	}

	if err := ClientSession.Cluster.CheckFeature(clusterName, featureName, values, &settings, 0); err != nil { // FIXME: define duration
		err = fail.FromGRPCStatus(err)
		msg := fmt.Sprintf("error checking Feature '%s' on Cluster '%s': %s", featureName, clusterName, err.Error())
		return clitools.FailureResponse(clitools.ExitOnRPC(msg))
	}

	msg := fmt.Sprintf("Feature '%s' found on cluster '%s'", featureName, clusterName)
	return clitools.SuccessResponse(msg)
}

// clusterFeatureRemoveCommand handles 'safescale cluster feature remove <cluster name> <pkgname>'
var clusterFeatureRemoveCommand = cli.Command{
	Name:      "remove",
	Aliases:   []string{"destroy", "delete", "rm", "uninstall"},
	Usage:     "Remove a feature from a cluster",
	ArgsUsage: "CLUSTERNAME FEATURENAME",
	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
		},
	},
	Action: clusterFeatureRemoveAction,
}

func clusterFeatureRemoveAction(c *cli.Context) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterFeatureCmdLabel, c.Command.Name, c.Args())
	if err := extractClusterName(c); err != nil {
		return clitools.FailureResponse(err)
	}

	featureName, err := extractFeatureArgument(c)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	values := parametersToMap(c.StringSlice("param"))
	settings := protocol.FeatureSettings{}
	// TODO: Reverse proxy rules are not yet purged when feature is removed, but current code
	// will try to apply them... Quick fix: Setting SkipProxy to true prevent this
	settings.SkipProxy = true

	if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
		description := "Remove cluster feature"
		pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
		go func() {
			for {
				if pb.IsFinished() {
					return
				}
				err := pb.Add(1)
				if err != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()

		defer func() {
			_ = pb.Finish()
		}()
	}

	if err := ClientSession.Cluster.RemoveFeature(clusterName, featureName, values, &settings, 0); err != nil {
		err = fail.FromGRPCStatus(err)
		msg := fmt.Sprintf("failed to remove Feature '%s' on Cluster '%s': %s", featureName, clusterName, err.Error())
		return clitools.FailureResponse(clitools.ExitOnRPC(msg))
	}
	return clitools.SuccessResponse(nil)
}

var clusterAnsibleCommands = cli.Command{
	Name:      "ansible",
	Usage:     "Administrative commands",
	ArgsUsage: "COMMAND",

	Subcommands: cli.Commands{
		clusterAnsibleInventoryCommands,
		clusterAnsibleRunCommands,
		clusterAnsiblePlaybookCommands,
	},
}

var clusterAnsibleInventoryCommands = cli.Command{
	Name:      "inventory",
	Category:  "Administrative commands",
	Usage:     "inventory CLUSTERNAME COMMAND [[--][PARAMS ...]]",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		// Set client session
		clientSession, xerr := client.New(c.String("server"), c.String("tenant"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Finding available master"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		// Get cluster master
		master, err := ClientSession.Cluster.FindAvailableMaster(clusterName, 0) // FIXME: set duration
		if err != nil {
			msg := fmt.Sprintf("No masters found available for the cluster '%s': %v", clusterName, err.Error())
			return clitools.ExitOnErrorWithMessage(exitcode.RPC, msg)
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			pb := progressbar.Default(-1, "Checking ansible feature")
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		// Check for feature
		values := map[string]string{} // FIXME feature is now "ansible-for-cluster" ?
		settings := protocol.FeatureSettings{}
		if err := ClientSession.Cluster.CheckFeature(clusterName, "ansible-for-cluster", values, &settings, 0); err != nil { // FIXME: define duration
			err = fail.FromGRPCStatus(err)
			msg := fmt.Sprintf("error checking Feature 'ansible' on Cluster '%s': %s", clusterName, err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}

		// Format arguments
		args := c.Args().Tail()
		var captureInventory = false
		// FIXME: Must set absolute inventory path, use "sudo -i" (interactive) with debian change $PATH, and makes fail ansible path finder (dirty way)
		// event not ~.ansible.cfg or ANSIBLE_CONFIG defined for user cladm (could be a solution ?)
		var filteredArgs []string
		inventoryPath := utils.BaseFolder + "/etc/ansible/inventory/inventory.py"
		for _, arg := range args {
			if captureInventory {
				inventoryPath = arg
				captureInventory = false
				continue
			}
			switch arg {
			case "-i":
			case "--inventory":
			case "--inventory-file": // DEPRECATED: deprecated
				/* Expect here
				[-i INVENTORY]
				*/
				captureInventory = true // extract given inventory (overload default inventoryPath)

			default:
				/* Expect here
				[-h | --help]
				[-v | --version]
				[--vault-id VAULT_IDS]
				[--ask-vault-password | --vault-password-file VAULT_PASSWORD_FILES]
				[--playbook-dir BASEDIR]
				[-e EXTRA_VARS]
				[--graph] [-y] [--toml] [--vars]
				[--export] [--output OUTPUT_FILE]
				[host|group]
				[--list | --host HOST] <- must have at least one
				*/
				filteredArgs = append(filteredArgs, arg)
			}
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Running ansible-inventory"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		// Make command line
		cmdStr := `sudo -u cladm -i ansible-inventory -i ` + inventoryPath + ` ` + strings.Join(filteredArgs, " ") // + useTLS
		logrus.Tracef(cmdStr)
		retcode, _ /*stdout*/, stderr, xerr := clientSession.SSH.Run(master.GetId(), cmdStr, outputs.DISPLAY, temporal.ConnectionTimeout(), 0)
		if xerr != nil {
			msg := fmt.Sprintf("failed to execute command on master '%s' of cluster '%s': %s", master.GetName(), clusterName, xerr.Error())
			return clitools.ExitOnErrorWithMessage(exitcode.RPC, msg)
		}
		if retcode != 0 {
			return cli.NewExitError(stderr, retcode)
		}
		return clitools.SuccessResponse(nil)
	},
}

var clusterAnsibleRunCommands = cli.Command{
	Name:      "run",
	Category:  "Administrative commands",
	Usage:     "run CLUSTERNAME COMMAND [[--][PARAMS ...]]",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		// Set client session
		clientSession, xerr := client.New(c.String("server"), c.String("tenant"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Running cluster command"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		// Get cluster master
		master, err := ClientSession.Cluster.FindAvailableMaster(clusterName, 0) // FIXME: set duration
		if err != nil {
			msg := fmt.Sprintf("No masters found available for the cluster '%s': %v", clusterName, err.Error())
			return clitools.ExitOnErrorWithMessage(exitcode.RPC, msg)
		}

		// Check for feature
		values := map[string]string{}
		settings := protocol.FeatureSettings{}
		if err := ClientSession.Cluster.CheckFeature(clusterName, "ansible", values, &settings, 0); err != nil { // FIXME: define duration
			err = fail.FromGRPCStatus(err)
			msg := fmt.Sprintf("error checking Feature 'ansible' on Cluster '%s': %s", clusterName, err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}

		// Format arguments
		args := c.Args().Tail()
		var captureInventory = false
		// FIXME: Must set absolute inventory path, use "sudo -i" (interactive) with debian change $PATH, and makes fail ansible path finder (dirty way)
		// event not ~.ansible.cfg or ANSIBLE_CONFIG defined for user cladm (could be a solution ?)
		var filteredArgs []string
		inventoryPath := utils.BaseFolder + "/etc/ansible/inventory/inventory.py"
		for _, arg := range args {
			if captureInventory {
				inventoryPath = arg
				captureInventory = false
				continue
			}
			switch arg {
			case "-i":
			case "--inventory":
			case "--inventory-file": // DEPRECATED: deprecated
				/* Expect here
				[-i INVENTORY]
				*/
				captureInventory = true // extract given inventory (overload default inventoryPath)

			default:
				/* Expect here
				[-h] [--version] [-v] [-b] [--become-method BECOME_METHOD] [--become-user USER]
				[-K] [--list-hosts]
				[-l SUBSET] [-P POLL_INTERVAL] [-B SECONDS] [-o] [-t TREE] [-k]
				[--private-key PRIVATE_KEY_FILE] [-u REMOTE_USER]
				[-c CONNECTION] [-T TIMEOUT]
				[--ssh-common-args SSH_COMMON_ARGS]
				[--sftp-extra-args SFTP_EXTRA_ARGS]
				[--scp-extra-args SCP_EXTRA_ARGS]
				[--ssh-extra-args SSH_EXTRA_ARGS] [-C] [--syntax-check] [-D]
				[-e EXTRA_VARS] [--vault-id VAULT_IDS]
				[--ask-vault-pass | --vault-password-file VAULT_PASSWORD_FILES]
				[-f FORKS] [-M MODULE_PATH] [--playbook-dir BASEDIR]
				[-a MODULE_ARGS] [-m MODULE_NAME]
				*/
				filteredArgs = append(filteredArgs, arg)
			}
		}

		// Make command line
		cmdStr := `sudo -u cladm -i ansible -i ` + inventoryPath + ` ` + strings.Join(filteredArgs, " ") // + useTLS
		logrus.Tracef(cmdStr)
		retcode, _ /*stdout*/, stderr, xerr := clientSession.SSH.Run(master.GetId(), cmdStr, outputs.DISPLAY, temporal.ConnectionTimeout(), 0)
		if xerr != nil {
			msg := fmt.Sprintf("failed to execute command on master '%s' of cluster '%s': %s", master.GetName(), clusterName, xerr.Error())
			return clitools.ExitOnErrorWithMessage(exitcode.RPC, msg)
		}
		if retcode != 0 {
			return cli.NewExitError(stderr, retcode)
		}
		return clitools.SuccessResponse(nil)
	},
}

var clusterAnsiblePlaybookCommands = cli.Command{
	Name:      "playbook",
	Category:  "Administrative commands",
	Usage:     "playbook CLUSTERNAME COMMAND [[--][PARAMS ...]]",
	ArgsUsage: "CLUSTERNAME",

	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)

		/*
			Ansible tree strcut required by ansible

			group_vars/ (f)
			hosts_vars/ (f)
			vars/ (f)
			library/ (f)
			module_utils/ (f)
			filter_plugins/ (f)
			tasks/ (f)
			roles/ (f)
			playbook.yml
			readme.md (f)

			Extension allows:
			.yml
			.md
			.j2 (role/[xxx]/templates)
			any (role/[xxx]/files)

		*/

		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err := extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			pb := progressbar.Default(-1, "Running ansible command")
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		// Check for feature
		values := map[string]string{}
		settings := protocol.FeatureSettings{}
		if err := ClientSession.Cluster.CheckFeature(clusterName, "ansible", values, &settings, 0); err != nil { // FIXME: define duration
			err = fail.FromGRPCStatus(err)
			msg := fmt.Sprintf("error checking Feature 'ansible' on Cluster '%s': %s", clusterName, err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}

		// Format arguments
		args := c.Args().Tail()
		var captureInventory = false
		var capturePlaybookFile = true
		var captureVaultFile = false
		var askForHelp = false
		var askForVault = false
		// FIXME: Must set absolute inventory path, use "sudo -i" (interactive) with debian change $PATH, and makes fail ansible path finder (dirty way)
		// event not ~.ansible.cfg or ANSIBLE_CONFIG defined for user cladm (could be a solution ?)
		// find no configuration for playbook defaut directory, must be absolute (arg: local file, mapped to remote)
		var ansibleDir = fmt.Sprintf("%s/ansible/", utils.EtcFolder)
		var inventoryPath = fmt.Sprintf("%sinventory/inventory.py", ansibleDir)
		var playbookFile = ""
		var vaultFile = ""
		var filteredArgs []string
		var isParam bool
		for _, arg := range args {
			isParam = arg[0] == '-'
			if isParam {
				capturePlaybookFile = false
			}
			if captureInventory {
				inventoryPath = arg
				captureInventory = false
				continue
			}
			if capturePlaybookFile {
				playbookFile = arg
				capturePlaybookFile = false
				continue
			}
			if captureVaultFile {
				vaultFile = arg
				captureVaultFile = false
				continue
			}
			switch arg {
			case "-i":
			case "--inventory":
			case "--inventory-file": // DEPRECATED: deprecated
				/* Expect here
				[-i INVENTORY]
				*/
				captureInventory = true // extract given inventory (overload default inventoryPath)
			case "--vault-password-file":
				captureVaultFile = true
			case "--ask-vault-pass":
				askForVault = true
			case "-h":
			case "--help":
				askForHelp = true
			default:
				/* Expect here
				[-h] [--version] [-v] [-b] [--become-method BECOME_METHOD] [--become-user USER]
				[-K] [--list-hosts]
				[-l SUBSET] [-P POLL_INTERVAL] [-B SECONDS] [-o] [-t TREE] [-k]
				[--private-key PRIVATE_KEY_FILE] [-u REMOTE_USER]
				[-c CONNECTION] [-T TIMEOUT]
				[--ssh-common-args SSH_COMMON_ARGS]
				[--sftp-extra-args SFTP_EXTRA_ARGS]
				[--scp-extra-args SCP_EXTRA_ARGS]
				[--ssh-extra-args SSH_EXTRA_ARGS] [-C] [--syntax-check] [-D]
				[-e EXTRA_VARS] [--vault-id VAULT_IDS]
				[--ask-vault-pass | --vault-password-file VAULT_PASSWORD_FILES]
				[-f FORKS] [-M MODULE_PATH]
				[-a MODULE_ARGS] [-m MODULE_NAME]
				*/
				filteredArgs = append(filteredArgs, arg)
			}

			if !isParam && !capturePlaybookFile {
				capturePlaybookFile = true
			}
		}

		// Ask for help
		if askForHelp {
			fmt.Print("" +
				"usage: safescale cluster ansible playbook CLUSTERNAME\n" +
				"    [-h, --help] [ -v, --version] [-k] [--private-key PRIVATE_KEY_FILE] [-u REMOTE_USER]\n" +
				"    [-c CONNECTION] [-T TIMEOUT] [--ssh-common-args SSH_COMMON_ARGS]\n" +
				"    [--sftp-extra-args SFTP_EXTRA_ARGS] [--scp-extra-args SCP_EXTRA_ARGS]\n" +
				"    [--ssh-extra-args SSH_EXTRA_ARGS] [--force-handlers] [--flush-cache] [-b]\n" +
				"    [--become-method BECOME_METHOD] [--become-user BECOME_USER] [-K] [-t TAGS]\n" +
				"    [--skip-tags SKIP_TAGS] [-C] [--syntax-check] [-D] [-i INVENTORY] [--list-hosts]\n" +
				"    [-l SUBSET] [-e EXTRA_VARS] [--vault-id VAULT_IDS]\n" +
				"    [--ask-vault-pass | --vault-password-file VAULT_PASSWORD_FILES] [-f FORKS] [-M MODULE_PATH]\n" +
				"    [--list-tasks] [--list-tags] [--step] [--start-at-task START_AT_TASK]\n" +
				"    playbook [playbook ...]\n" +
				"\n" +
				"Runs Ansible playbooks, executing the defined tasks on the targeted hosts.\n" +
				"\n" +
				"positional arguments:\n" +
				"playbook                                        Playbook(s). Accept .yml file, or .zip archive with playbook.yml file and dependencies with following tree struct :\n" +
				"                                                group_vars/        (facultative)\n" +
				"                                                hosts_vars/        (facultative)\n" +
				"                                                vars/              (facultative)\n" +
				"                                                library/           (facultative)\n" +
				"                                                module_utils/      (facultative)\n" +
				"                                                filter_plugins/    (facultative)\n" +
				"                                                tasks/             (facultative)\n" +
				"                                                roles/             (facultative)\n" +
				"                                                requirements.yml   (facultative) used for declare dependencies, trigger ansible-galaxy imports\n" +
				"                                                .vault             (facultative) vault file exchange \n" +
				"                                                playbook.yml\n" +
				"\n" +
				"optional arguments:\n" +
				"--ask-vault-pass                                ask for vault password\n" +
				"--flush-cache                                   clear the fact cache for every host in inventory\n" +
				"--force-handlers                                run handlers even if a task fails\n" +
				"--list-hosts                                    outputs a list of matching hosts; does not execute anything else\n" +
				"--list-tags                                     list all available tags\n" +
				"--list-tasks                                    list all tasks that would be executed\n" +
				"--skip-tags SKIP_TAGS                           only run plays and tasks whose tags do not match these values\n" +
				"--start-at-task START_AT_TASK                   start the playbook at the task matching this name\n" +
				"--step                                          one-step-at-a-time: confirm each task before running\n" +
				"--syntax-check                                  perform a syntax check on the playbook, but do not execute it\n" +
				"--vault-id VAULT_IDS                            the vault identity to use\n" +
				"--vault-password-file VAULT_PASSWORD_FILES      vault password file\n" +
				"--version                                       show program's version number, config file location, configured module search path, module\n" +
				"                                                location, executable location and exit\n" +
				"-C, --check                                     don't make any changes; instead, try to predict some of the changes that may occur\n" +
				"-D, --diff                                      when changing (small) files and templates, show the differences in those files; works great\n" +
				"                                                with --check\n" +
				"(-M | --module-path) MODULE_PATH                prepend colon-separated path(s) to module library\n" +
				"                                                (default=~/.ansible/plugins/modules:/usr/share/ansible/plugins/modules)\n" +
				"(-e | --extra-vars) EXTRA_VARS                  set additional variables as key=value or YAML/JSON, if filename prepend with @\n" +
				"(-f | --forks) FORKS                            specify number of parallel processes to use (default=5)\n" +
				"'-h | --help)                                   show this help message and exit\n" +
				"(-i | --inventory ) INVENTORY	                 specify inventory host path or comma separated host list\n" +
				"(-l | --limit) SUBSET                           further limit selected hosts to an additional pattern\n" +
				"(-t | --tags)  TAGS                             only run plays and tasks tagged with these values\n" +
				"(-v | --verbose )                               verbose mode (-vvv for more, -vvvv to enable connection debugging)\n" +
				"\n" +
				"Connection Options:\n" +
				"control as whom and how to connect to hosts\n" +
				"\n" +
				"(--private-key | --key-file) PRIVATE_KEY_FILE   use this file to authenticate the connection\n" +
				"--scp-extra-args SCP_EXTRA_ARGS                 specify extra arguments to pass to scp only (e.g. -l)\n" +
				"--sftp-extra-args SFTP_EXTRA_ARGS               specify extra arguments to pass to sftp only (e.g. -f, -l)\n" +
				"--ssh-common-args SSH_COMMON_ARGS               specify common arguments to pass to sftp/scp/ssh (e.g. ProxyCommand)\n" +
				"--ssh-extra-args SSH_EXTRA_ARGS                 specify extra arguments to pass to ssh only (e.g. -R)\n" +
				"(-T | --timeout ) TIMEOUT                       override the connection timeout in seconds (default=10)\n" +
				"(-c | --connection ) CONNECTION                 connection type to use (default=smart)\n" +
				"(-k | --ask-pass )                              ask for connection password\n" +
				"(-u | --user ) REMOTE_USER                      connect as this user (default=None)\n" +
				"\n" +
				"Privilege Escalation Options:\n" +
				"control how and which user you become as on target hosts\n" +
				"\n" +
				"--become-method BECOME_METHOD                   privilege escalation method to use (default=sudo), use `ansible-doc -t become -l` to list valid choices.\n" +
				"--become-user BECOME_USER                       run operations as this user (default=root)\n" +
				"(-K | --ask-become-pass)                        ask for privilege escalation password\n" +
				"(-b | --become )                                run operations with become (does not imply password prompting)\n")
			return nil
		}

		logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Command.Name, c.Args())
		err = extractClusterName(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		// Set client session
		clientSession, xerr := client.New(c.String("server"), c.String("tenant"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		// Check for feature
		values = map[string]string{}
		settings = protocol.FeatureSettings{}
		if err := clientSession.Cluster.CheckFeature(clusterName, "ansible", values, &settings, 0); err != nil { // FIXME: define duration
			err = fail.FromGRPCStatus(err)
			msg := fmt.Sprintf("error checking Feature \"ansible\" on Cluster '%s': %s", clusterName, err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}

		err = playAnsible(c, clientSession, playbookFile, askForVault, vaultFile, ansibleDir, inventoryPath, filteredArgs)
		if err != nil {
			switch err.(type) {
			case *cli.ExitError:
				return clitools.FailureResponse(err)
			default:
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
			}
		}

		return clitools.SuccessResponse(nil)
	},
}

func playAnsible(c *cli.Context, clientSession *client.Session, playbookFile string, askForVault bool, vaultFile string, ansibleDir string, inventoryPath string, filteredArgs []string) error {
	var treeStruct = []string{
		"group_vars",
		"hosts_vars",
		"vars",
		"library",
		"module_utils",
		"filter_plugins",
		"tasks",
		"roles",
	}

	// Must set playbook file
	if playbookFile == "" {
		return fmt.Errorf("expect a playbook file for cluster '%s'", clusterName)
	}

	// Check local file exists
	stat, err := os.Stat(playbookFile)
	if os.IsNotExist(err) {
		return fmt.Errorf("playbook file not found for cluster '%s'", clusterName)
	}
	if !stat.Mode().IsRegular() {
		return fmt.Errorf("playbook is not regular file, for cluster '%s'", clusterName)
	}

	// Check extension
	var playbookExtension = ""
	pos := strings.LastIndex(playbookFile, ".")
	if pos >= 0 {
		playbookExtension = strings.ToLower(playbookFile[pos+1:])
	}

	// Temporary working directory
	tmpDirectory := fmt.Sprintf("%s/safescale-ansible-playbook/", os.TempDir())
	err = os.RemoveAll(tmpDirectory)
	if err != nil {
		return err
	}
	err = os.Mkdir(tmpDirectory, 0755)
	if err != nil {
		return err
	}

	var list []string
	switch playbookExtension {
	case "yml":
		// Copy to tmp workdir
		err = func(playbookFile string, tmpDirectory string) (err error) {
			source, err := os.Open(playbookFile)
			if err != nil {
				return err
			}
			defer func(source *os.File) {
				err := source.Close()
				if err != nil {
					logrus.Debugf(err.Error())
				}
			}(source)
			destination, err := os.Create(fmt.Sprintf("%s/playbook.yml", tmpDirectory))
			if err != nil {
				return err
			}
			defer func(destination *os.File) {
				err := destination.Close()
				if err != nil {
					logrus.Debugf(err.Error())
				}
			}(destination)
			_, err = io.Copy(destination, source)
			if err != nil {
				return err
			}
			return nil

		}(playbookFile, tmpDirectory)

		if err != nil {
			return fmt.Errorf("playbook copy to working directory fail for cluster '%s': %w", clusterName, err)
		}

		list = []string{"playbook.yml"}
	case "zip":
		// Check archive content
		list, err = func(archivePath string, tmpDirectory string) ([]string, error) {
			archive, err := zip.OpenReader(playbookFile)
			if err != nil {
				return nil, err
			}
			defer func(archive *zip.ReadCloser) {
				err := archive.Close()
				if err != nil {
					logrus.Debugf(err.Error())
				}
			}(archive)

			list = []string{}

			var foundPlaybook = false
			for _, f := range archive.File {
				p, err := filepath.Abs(f.Name)
				if err != nil {
					return nil, fmt.Errorf("problem reading playbook: %w", err)
				}
				if !strings.Contains(p, "..") {
					if !f.FileInfo().IsDir() {
						// Check if file path is allowed in ansible tree struct (ignore empty directories)
						err := func(path string, allowDirs []string) error {
							pos := strings.Index(path, "/")
							if pos >= 0 {
								fileBaseDir := path[:pos]
								found := false
								for _, v := range allowDirs {
									if v == fileBaseDir {
										found = true
										break
									}
								}
								if !found {
									return fmt.Errorf(fmt.Sprintf("file path '%s' not allow in ansible tree struct", path))
								}
							}
							return nil
						}(f.Name, treeStruct)
						if err != nil {
							return nil, err
						}

						nerr := func() error {
							// Playbook
							if f.Name == "playbook.yml" {
								foundPlaybook = true
							}

							// Unzip contain to temporary location
							path := fmt.Sprintf("%s%s", tmpDirectory, f.Name)
							if strings.Contains(path, "..") {
								return fmt.Errorf("unsanitized path")
							}
							err = os.MkdirAll(filepath.Dir(path), os.ModePerm)
							if err != nil {
								return err
							}

							dstFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
							defer func(afi *os.File) {
								err := afi.Close()
								if err != nil {
									logrus.Debugf(err.Error())
								}
							}(dstFile)
							if err != nil {
								return err
							}
							fileInArchive, err := f.Open()
							defer func(afi *io.ReadCloser) {
								err := (*afi).Close()
								if err != nil {
									logrus.Debugf(err.Error())
								}
							}(&fileInArchive)

							if err != nil {
								return err
							}
							_, err = io.Copy(dstFile, fileInArchive)
							if err != nil {
								return err
							}

							// Add filepath to valid files in archives
							list = append(list, f.Name)
							return nil
						}()

						if nerr != nil {
							return nil, nerr
						}
					}
				}
			}
			if !foundPlaybook {
				return nil, fmt.Errorf("archive has no playbook file \"playbook.yml\" on it's root")
			}

			return list, nil
		}(playbookFile, tmpDirectory)
		if err != nil {
			return fmt.Errorf("playbook archive invalid '%s': %w", clusterName, err)
		}
	default:
		return fmt.Errorf("playbook file extention expect .yml or .zip, (unexpected %s) for cluster '%s'", playbookExtension, clusterName)
	}

	// Ask for vault password ? (map it to vault-file)
	if askForVault {
		err = func(tmpDirectory string) error {
			fmt.Print("> Prompt vault password : ")
			reader := bufio.NewReader(os.Stdin)
			vaultPassword, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			vaultPassword = strings.TrimSpace(vaultPassword)
			destination, err := os.Create(fmt.Sprintf("%s/.vault", tmpDirectory))
			if err != nil {
				return err
			}
			defer func(destination *os.File) {
				err := destination.Close()
				if err != nil {
					logrus.Debugf(err.Error())
				}
			}(destination)
			_, err = destination.WriteString(vaultPassword)
			if err != nil {
				return err
			}
			return nil
		}(tmpDirectory)

		if err != nil {
			return fmt.Errorf("fail to read vault password for cluster '%s': %w", clusterName, err)
		}
		list = append(list, ".vault")
	} else if vaultFile != "" { // Check for vault file
		stat, err := os.Stat(vaultFile)
		if os.IsNotExist(err) {
			return fmt.Errorf("playbook vault file not found for cluster '%s'", clusterName)
		}
		if !stat.Mode().IsRegular() {
			return fmt.Errorf("playbook vault file is not regular file, for cluster '%s'", clusterName)
		}
		// Copy to tmp workdir
		err = func(vaultFile string, tmpDirectory string) (err error) {
			source, err := os.Open(vaultFile)
			if err != nil {
				return err
			}
			defer func(source *os.File) {
				err := source.Close()
				if err != nil {
					logrus.Debugf(err.Error())
				}
			}(source)
			destination, err := os.Create(fmt.Sprintf("%s/.vault", tmpDirectory))
			if err != nil {
				return err
			}
			defer func(destination *os.File) {
				err := destination.Close()
				if err != nil {
					logrus.Debugf(err.Error())
				}
			}(destination)
			_, err = io.Copy(destination, source)
			if err != nil {
				return err
			}
			return nil

		}(vaultFile, tmpDirectory)
		if err != nil {
			return fmt.Errorf("playbook vault file copy failed for cluster '%s': %w", clusterName, err)
		}
		list = append(list, ".vault")
	}

	// Make cleaned archive
	err = func(tmpDirectory string, list []string, playBookArchivePath string) (err error) {
		archive, err := os.Create(playBookArchivePath)
		if err != nil {
			return fmt.Errorf("fail to create cleaned playbook archive for cluster '%s': %w", clusterName, err)
		}
		defer func(afi *os.File) {
			err := afi.Close()
			if err != nil {
				logrus.Debugf(err.Error())
			}
		}(archive)

		zipWriter := zip.NewWriter(archive)
		defer func(zipWriter *zip.Writer) {
			err := zipWriter.Close()
			if err != nil {
				logrus.Debugf(err.Error())
			}
		}(zipWriter)

		for _, path := range list {
			path := path
			if strings.Contains(path, "..") {
				return fmt.Errorf("unsanitzed path")
			}
			fpFrom, err := os.Open(fmt.Sprintf("%s%s", tmpDirectory, path))
			if err != nil {
				return err
			}

			//goland:noinspection ALL
			defer func(afi *os.File) { // nolint
				err := afi.Close()
				if err != nil {
					logrus.Debugf(err.Error())
				}
			}(fpFrom)

			var fpTo io.Writer
			fpTo, err = zipWriter.Create(path)
			if err != nil {
				return err
			}
			if _, err := io.Copy(fpTo, fpFrom); err != nil {
				return err
			}
		}
		return nil

	}(tmpDirectory, list, fmt.Sprintf("%splaybook.zip", tmpDirectory))

	if err != nil {
		return fmt.Errorf("failed to make cleaned playbook archive for cluster '%s': %w", clusterName, err)
	}

	// Upload playbook archive
	valuesOnRemote := &client.RemoteFilesHandler{}
	rfc := client.RemoteFileItem{
		Local:  fmt.Sprintf("%splaybook.zip", tmpDirectory),
		Remote: fmt.Sprintf("%s/ansible_playbook.zip", utils.TempFolder),
	}
	valuesOnRemote.Add(&rfc)

	// If vault file, set it to absolute
	if vaultFile != "" || askForVault {
		vaultFile = fmt.Sprintf(" --vault-password-file %s.vault", ansibleDir)
	}

	// Unzip archive to final destination and run playbook
	cmdStr := fmt.Sprintf(
		"sudo chown cladm:root %s && sudo chmod 0774 %s && sudo -u cladm unzip -o %s -d %s && ([ -f %srequirements.yml ] && sudo -u cladm -i ansible-galaxy install -r %srequirements.yml || true) && sudo -u cladm -i ansible-playbook %splaybook.yml -i %s%s %s",
		rfc.Remote,
		rfc.Remote,
		rfc.Remote,
		ansibleDir,
		ansibleDir,
		ansibleDir,
		ansibleDir,
		inventoryPath,
		vaultFile,
		strings.Join(filteredArgs, " "),
	)

	// Run playbook
	err = executeCommand(clientSession, cmdStr, valuesOnRemote, outputs.DISPLAY)
	if err != nil {
		return err
	}

	// Even if command fail, must delete remote files as possible
	cmdStr = ""
	for _, v := range list {
		cmdStr = fmt.Sprintf("%s sudo -u cladm rm -f %s%s &&", cmdStr, ansibleDir, v)
	}
	cmdStr = fmt.Sprintf("%s sudo -u cladm rm -f %splaybook.zip", cmdStr, tmpDirectory)

	err = executeCommand(clientSession, cmdStr, valuesOnRemote, outputs.DISPLAY)
	if err != nil {
		return err
	}

	// Clean temporaries (local)
	err = os.RemoveAll(tmpDirectory)
	if err != nil {
		return fmt.Errorf("failed to run playbook for cluster '%s': %w", clusterName, err)
	}
	return nil
}
