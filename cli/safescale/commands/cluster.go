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
	log "github.com/sirupsen/logrus"
	"os"
	"strings"

	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/cluster"
	"github.com/CS-SI/SafeScale/lib/server/cluster/api"
	"github.com/CS-SI/SafeScale/lib/server/cluster/control"
	clusterpropsv1 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Flavor"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Property"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/install"
	"github.com/CS-SI/SafeScale/lib/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/enums/ExitCode"
)

var (
	clusterName string
	// clusterServiceName *string
	clusterInstance api.Cluster
)

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
		//clusterSshCommand,
		clusterStartCommand,
		clusterStopCommand,
		clusterExpandCommand,
		clusterShrinkCommand,
		clusterDcosCommand,
		clusterKubectlCommand,
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
		clusterInstance, err = cluster.Get(concurrency.RootTask(), clusterName)
		if err != nil {
			if _, ok := err.(resources.ErrResourceNotFound); ok {
				if !c.Command.HasName("create") {
					return clitools.ExitOnErrorWithMessage(ExitCode.NotFound, fmt.Sprintf("Cluster '%s' not found.\n", clusterName))
				}
			} else {
				msg := fmt.Sprintf("Failed to query for cluster '%s': %s\n", clusterName, err.Error())
				return clitools.ExitOnRPC(msg)
			}
		} else {
			if c.Command.HasName("create") {
				return clitools.ExitOnErrorWithMessage(ExitCode.Duplicate, fmt.Sprintf("Cluster '%s' already exists.\n", clusterName))
			}
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
		response := utils.NewCliResponse()

		list, err := cluster.List()
		if err != nil {
			_ = response.Failed(clitools.ExitOnRPC(fmt.Sprintf("Failed to get cluster list: %v", err)))
		} else {
			var formatted []interface{}
			for _, value := range list {
				c := value.(api.Cluster)
				converted, err := convertToMap(c)
				if err != nil {
					return response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, fmt.Sprintf("failed to extract data about cluster '%s'", c.GetIdentity(concurrency.RootTask()).Name)))
				}
				formatted = append(formatted, formatClusterConfig(converted, false))
			}
			response.Succeeded(formatted)
		}

		return response.GetErrorWithoutMessage()
	},
}

// formatClusterConfig...
func formatClusterConfig(value interface{}, detailed bool) map[string]interface{} {
	core := value.(map[string]interface{})

	delete(core, "keypair")
	if !detailed {
		delete(core, "admin_login")
		delete(core, "admin_password")
		delete(core, "defaults")
		delete(core, "features")
		delete(core, "gateway_ip")
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
	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> inspect`,
	// 		Description: `
	// Displays information about the cluster 'clustername'.`,
	// 	},
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			_ = response.Failed(err)
		} else {
			clusterConfig, err := outputClusterConfig()
			if err != nil {
				_ = response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error()))
			} else {
				response.Succeeded(clusterConfig)
			}
		}

		return response.GetErrorWithoutMessage()
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
	err := properties.LockForRead(Property.CompositeV1).ThenUse(func(v interface{}) error {
		result["tenant"] = v.(*clusterpropsv1.Composite).Tenants[0]
		return nil
	})
	if err != nil {
		return nil, err
	}

	netCfg := c.GetNetworkConfig(concurrency.RootTask())
	result["network_id"] = netCfg.NetworkID
	result["cidr"] = netCfg.CIDR
	result["gateway_ip"] = netCfg.GatewayIP
	result["public_ip"] = netCfg.PublicIP

	err = properties.LockForRead(Property.DefaultsV1).ThenUse(func(v interface{}) error {
		defaultsV1 := v.(*clusterpropsv1.Defaults)
		result["defaults"] = map[string]interface{}{
			"image":  defaultsV1.Image,
			"master": defaultsV1.MasterSizing,
			"node":   defaultsV1.NodeSizing,
		}
		return nil
	})

	err = properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		result["nodes"] = map[string]interface{}{
			"masters": nodesV1.Masters,
			"nodes":   nodesV1.PrivateNodes,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = properties.LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		result["features"] = v.(*clusterpropsv1.Features)
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = properties.LockForRead(Property.StateV1).ThenUse(func(v interface{}) error {
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
		remoteDesktops := []string{}
		clientHost := client.New().Host
		gwPublicIP := netCfg.PublicIP
		for _, id := range c.ListMasterIDs(concurrency.RootTask()) {
			host, err := clientHost.Inspect(id, client.DefaultExecutionTimeout)
			if err != nil {
				return nil, err
			}
			remoteDesktops = append(remoteDesktops, fmt.Sprintf("https://%s/remotedesktop/%s/", gwPublicIP, host.Name))
		}
		result["remote_desktop"] = remoteDesktops
	} else {
		result["remote_desktop"] = fmt.Sprintf("Remote Desktop not installed. To install it, execute 'deploy cluster %s feature remotedesktop add'.", clusterName)
	}

	return result, nil
}

// clusterCreateCmd handles 'deploy cluster <clustername> create'
var clusterCreateCommand = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create a cluster",
	ArgsUsage: "CLUSTERNAME: name of the cluster to create",

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
			Usage: "Allows to disable addition of default features",
		},
		cli.StringFlag{
			Name:  "os",
			Usage: "Defines the operating system to use",
		},
		cli.UintFlag{
			Name:  "cpu",
			Usage: "Defines the number of cpu of masters and nodes in the cluster",
		},
		cli.Float64Flag{
			Name:  "ram",
			Usage: "Defines the size of RAM of masters and nodes in the cluster (in GB)",
		},
		cli.UintFlag{
			Name:  "disk",
			Usage: "Defines the size of system disk of masters and nodes (in GB)",
		},
	},

	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			return response.Failed(err)
		}

		complexityStr := c.String("complexity")
		complexity, err := Complexity.Parse(complexityStr)
		if err != nil {
			msg := fmt.Sprintf("Invalid option --complexity|-C: %s\n", err.Error())
			return response.Failed(clitools.ExitOnInvalidOption(msg))
		}

		flavorStr := c.String("flavor")
		flavor, err := Flavor.Parse(flavorStr)
		if err != nil {
			msg := fmt.Sprintf("Invalid option --flavor|-F: %s\n", err.Error())
			return response.Failed(clitools.ExitOnInvalidOption(msg))
		}

		keep := c.Bool("keep-on-failure")

		cidr := c.String("cidr")

		disable := c.StringSlice("disable")
		disableFeatures := map[string]struct{}{}
		for _, v := range disable {
			disableFeatures[v] = struct{}{}
		}

		los := c.String("os")
		if flavor == Flavor.DCOS {
			// DCOS forces to use RHEL/CentOS/CoreOS, and we've chosen to use CentOS, so ignore --os option
			los = ""
		}

		cpu := int32(c.Uint("cpu"))
		ram := float32(c.Float64("ram"))
		disk := int32(c.Uint("disk"))

		var nodesDef *resources.HostDefinition
		if cpu > 0 || ram > 0.0 || disk > 0 || los != "" {
			nodesDef = &resources.HostDefinition{
				Cores:     int(cpu),
				RAMSize:   ram,
				DiskSize:  int(disk),
				ImageID:   los,
				GPUNumber: -1, // Clusters currently don't take gpus into account
			}
		}
		clusterInstance, err = cluster.Create(concurrency.RootTask(), control.Request{
			Name:                    clusterName,
			Complexity:              complexity,
			CIDR:                    cidr,
			Flavor:                  flavor,
			KeepOnFailure:           keep,
			NodesDef:                nodesDef,
			DisabledDefaultFeatures: disableFeatures,
		})
		if err != nil {
			if clusterInstance != nil {
				_ = clusterInstance.Delete(concurrency.RootTask())
			}
			msg := fmt.Sprintf("failed to create cluster: %s\n", err.Error())
			_ = response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, msg))
		} else {
			toFormat, err := convertToMap(clusterInstance)
			if err != nil {
				_ = response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error()))
			} else {
				formatted := formatClusterConfig(toFormat, true)
				if !Debug {
					delete(formatted, "defaults")
				}
				response.Succeeded(formatted)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

// clusterDeleteCmd handles 'deploy cluster <clustername> delete'
var clusterDeleteCommand = cli.Command{
	Name:      "delete",
	Aliases:   []string{"destroy", "remove", "rm"},
	Usage:     "delete CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> delete|destroy|remove|rm [-y]`,
	// 		Options: []string{`
	// options:
	//   -y,--assume-yes  Don't ask for confirmation`,
	// 		},
	// 		Description: `
	// Delete a cluster.`,
	// 	},

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "assume-yes, yes, y",
		},
		cli.BoolFlag{
			Name: "force, f",
		},
	},

	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			_ = response.Failed(err)
		} else {
			yes := c.Bool("assume-yes")
			force := c.Bool("force")

			if !yes && !utils.UserConfirmed(fmt.Sprintf("Are you sure you want to delete Cluster '%s'", clusterName)) {
				response.Succeeded("Aborted")
			} else {
				if force {
					log.Println("'-f,--force' does nothing yet")
				}

				err = clusterInstance.Delete(concurrency.RootTask())
				if err != nil {
					_ = response.Failed(clitools.ExitOnRPC(err.Error()))
				} else {
					response.Succeeded(nil)
				}
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

// clusterStopCmd handles 'deploy cluster <clustername> stop'
var clusterStopCommand = cli.Command{
	Name:      "stop",
	Aliases:   []string{"freeze", "halt"},
	Usage:     "stop CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> stop|freeze`,
	// 		Description: `
	// Stop the cluster (make it unavailable for duty).`,
	// 	},

	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			_ = response.Failed(err)
		} else {
			err = clusterInstance.Stop(concurrency.RootTask())
			if err != nil {
				_ = response.Failed(clitools.ExitOnRPC(err.Error()))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

var clusterStartCommand = cli.Command{
	Name:      "start",
	Aliases:   []string{"unfreeze"},
	Usage:     "start CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",
	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> start|unfreeze`,
	// 		Options: []string{`
	// options:
	//   --force, -f Force Don't ask for confirmation`,
	// 		},
	// 		Description: `
	// Start the cluster (make it available for duty).`,
	// 	},
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			_ = response.Failed(err)
		} else {
			err = clusterInstance.Start(concurrency.RootTask())
			if err != nil {
				_ = response.Failed(clitools.ExitOnRPC(err.Error()))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

// clusterStateCmd handles 'deploy cluster <clustername> state'
var clusterStateCommand = cli.Command{
	Name:      "state",
	Usage:     "state CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> state`,
	// 		Description: `
	// Get the cluster state.`,
	// 	},
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			_ = response.Failed(err)
		} else {
			state, err := clusterInstance.GetState(concurrency.RootTask())
			if err != nil {
				msg := fmt.Sprintf("failed to get cluster state: %s", err.Error())
				_ = response.Failed(clitools.ExitOnRPC(msg))
			} else {
				response.Succeeded(map[string]interface{}{
					"Name":       clusterName,
					"State":      state,
					"StateLabel": state.String(),
				})
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

// clusterExpandCmd handles 'deploy cluster <clustername> expand'
var clusterExpandCommand = cli.Command{
	Name:      "expand",
	Usage:     "expand CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> expand [{command options}] [{host options}]`,
	// 		Options: []string{
	// 			`
	// command options:
	//   --count,-n <number of nodes> Instructs to expand cluster with <number> of new nodes
	//   --public,-p                  Allocates public IP address(es) to node(s)`,
	// 			`
	// host options:
	//   --os <operating system> (default: Ubuntu 18.04)
	//   --cpu <number of cpus> (default: 4)
	//   --ram <ram size) (default: 15 GB)
	//   --disk <disk size> (default: 100 GB)`,
	// 		},
	// 		Description: `
	// Expand the cluster by adding nodes.`,
	// 	},

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
	},
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			_ = response.Failed(err)
		} else {
			count := int(c.Uint("count"))
			if count == 0 {
				count = 1
			}
			los := c.String("os")
			cpu := int32(c.Uint("cpu"))
			ram := float32(c.Float64("ram"))
			disk := int32(c.Uint("disk"))
			//gpu := c.Bool("gpu")
			_ = c.Bool("gpu")

			// err := createNodes(clusterName, public, count, los, cpu, ram, disk)
			var nodeRequest *resources.HostDefinition
			if los != "" || cpu > 0 || ram > 0.0 || disk > 0 {
				nodeRequest = &resources.HostDefinition{
					Cores:     int(cpu),
					RAMSize:   ram,
					DiskSize:  int(disk),
					ImageID:   los,
					GPUNumber: -1, // Clusters currently don't take gpus into account
				}
			}
			hosts, err := clusterInstance.AddNodes(concurrency.RootTask(), count, nodeRequest)
			if err != nil {
				_ = response.Failed(clitools.ExitOnRPC(err.Error()))
			} else {
				response.Succeeded(hosts)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

// clusterShrinkCommand handles 'deploy cluster <clustername> shrink'
var clusterShrinkCommand = cli.Command{
	Name:      "shrink",
	Usage:     "shrink CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> shrink [{command options}]`,
	// 		Options: []string{
	// 			`
	// command options:
	//   -n,--count <number of nodes>  Number of nodes to delete from the cluster`,
	// 		},
	// 		Description: `
	// Shrink cluster by removing last added node(s).`,
	// 	},

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
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			_ = response.Failed(err)
		} else {
			count := c.Uint("count")
			yes := c.Bool("yes")

			var countS string
			if count > 1 {
				countS = "s"
			}
			present := clusterInstance.CountNodes(concurrency.RootTask())
			if count > present {
				msg := fmt.Sprintf("can't delete %d node%s, the cluster contains only %d of them", count, countS, present)
				return response.Failed(clitools.ExitOnInvalidOption(msg))
			}

			if !yes {
				msg := fmt.Sprintf("Are you sure you want to delete %d node%s from Cluster %s", count, countS, clusterName)
				if !utils.UserConfirmed(msg) {
					response.Succeeded("Aborted")
				}
			}

			fmt.Printf("Deleting %d node%s from Cluster '%s' (this may take a while)...\n", count, countS, clusterName)
			var msgs []string
			availableMaster, err := clusterInstance.FindAvailableMaster(concurrency.RootTask())
			if err != nil {
				return response.Failed(err)
			}
			for i := uint(0); i < count; i++ {
				err := clusterInstance.DeleteLastNode(concurrency.RootTask(), availableMaster)
				if err != nil {
					msgs = append(msgs, fmt.Sprintf("Failed to delete node #%d: %s", i+1, err.Error()))
				}
			}
			if len(msgs) > 0 {
				_ = response.Failed(clitools.ExitOnRPC(strings.Join(msgs, "\n")))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

var clusterDcosCommand = cli.Command{
	Name:      "dcos",
	Category:  "Administrative commands",
	Usage:     "dcos CLUSTERNAME [COMMAND ...]",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> dcos [<arg>...]`,
	// 		Description: `
	// Executes DCOS cli on an available DCOS master.
	// Is meaningful only for a cluster using DCOS flavor.`,
	// 	},

	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			_ = response.Failed(err)
		} else {
			identity := clusterInstance.GetIdentity(concurrency.RootTask())
			if identity.Flavor != Flavor.DCOS {
				msg := fmt.Sprintf("Can't call dcos on this cluster, its flavor isn't DCOS (%s).\n", identity.Flavor.String())
				_ = response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.NotApplicable, msg))
			} else {
				args := c.Args().Tail()
				cmdStr := "sudo -u cladm -i dcos " + strings.Join(args, " ")
				err = executeCommand(cmdStr)
				if err != nil {
					_ = response.Failed(err)
				} else {
					response.Succeeded(nil)
				}
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

var clusterKubectlCommand = cli.Command{
	Name:      "kubectl",
	Category:  "Administrative commands",
	Usage:     "kubectl CLUSTERNAME [COMMAND ...]",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> kubectl [-- <arg>...]`,
	// 		Description: `
	// Executes kubectl cli on the cluster.
	// Is meaningful only for a cluster where Kubernetes service is installed and running.`,
	// 	},

	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			_ = response.Failed(err)
		} else {
			args := c.Args().Tail()
			cmdStr := "sudo -u cladm -i kubectl " + strings.Join(args, " ")
			err = executeCommand(cmdStr)
			if err != nil {
				_ = response.Failed(err)
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

var clusterRunCommand = cli.Command{
	Name:      "run",
	Aliases:   []string{"execute", "exec"},
	Usage:     "run CLUSTERNAME COMMAND",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster list,ls
	//        {{.ProgName}} [options] cluster <clustername> run args[,args...]`,
	// 	},

	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			_ = response.Failed(err)
		}

		_ = response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.NotImplemented, "clusterRunCmd not yet implemented"))

		return response.GetErrorWithoutMessage()
	},
}

func executeCommand(command string) error {
	masters := clusterInstance.ListMasterIDs(concurrency.RootTask())
	if len(masters) <= 0 {
		msg := fmt.Sprintf("No masters found for the cluster '%s'", clusterInstance.GetIdentity(concurrency.RootTask()).Name)
		return clitools.ExitOnErrorWithMessage(ExitCode.Run, msg)
	}
	safescalessh := client.New().Ssh
	for i, m := range masters {
		retcode, stdout, stderr, err := safescalessh.Run(m, command, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to execute command on master #%d: %s", i+1, err.Error())
			if i+1 < len(masters) {
				_, _ = fmt.Fprintln(os.Stderr, "Trying another master...")
				continue
			}
		}
		if retcode != 0 {
			output := stdout
			if output != "" {
				output += "\n"
			}
			output += stderr
			// _, _ = fmt.Fprintf(os.Stderr, "Run on master #%d, retcode=%d\n%s\n", i+1, retcode, output)
			return clitools.ExitOnRPC(output)
		}
		fmt.Println(stdout)
		return nil
	}

	return clitools.ExitOnRPC("failed to find an available master server to execute the command.")
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
		response := utils.NewCliResponse()

		features, err := install.ListFeatures("cluster")
		if err != nil {
			_ = response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error()))
		} else {
			response.Succeeded(features)
		}

		return response.GetErrorWithoutMessage()
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
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			return response.Failed(err)
		}
		err = extractFeatureArgument(c)
		if err != nil {
			return response.Failed(err)
		}

		feature, err := install.NewFeature(concurrency.RootTask(), featureName)
		if err != nil {
			return response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error()))
		}
		if feature == nil {
			msg := fmt.Sprintf("Failed to find a feature named '%s'.\n", featureName)
			return response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.NotFound, msg))
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

		target := install.NewClusterTarget(concurrency.RootTask(), clusterInstance)
		results, err := feature.Add(target, values, settings)
		if err != nil {
			msg := fmt.Sprintf("Error installing feature '%s' on cluster '%s': %s\n", featureName, clusterName, err.Error())
			_ = response.Failed(clitools.ExitOnRPC(msg))
		} else {
			if !results.Successful() {
				msg := fmt.Sprintf("Failed to install feature '%s' on cluster '%s'", featureName, clusterName)
				if Debug || Verbose {
					msg += fmt.Sprintf(":\n%s", results.AllErrorMessages())
				}
				_ = response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, msg))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
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
		response := utils.NewCliResponse()
		err := extractClusterArgument(c)
		if err != nil {
			return response.Failed(err)
		}
		err = extractFeatureArgument(c)
		if err != nil {
			return response.Failed(err)
		}
		feature, err := install.NewFeature(concurrency.RootTask(), featureName)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err.Error())
			return response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error()))
		}
		if feature == nil {
			msg := fmt.Sprintf("Failed to find a feature named '%s'.\n", featureName)
			return response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.NotFound, msg))
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

		target := install.NewClusterTarget(concurrency.RootTask(), clusterInstance)
		results, err := feature.Check(target, values, settings)
		if err != nil {
			msg := fmt.Sprintf("Error checking if feature '%s' is installed on '%s': %s\n", featureName, clusterName, err.Error())
			_ = response.Failed(clitools.ExitOnRPC(msg))
		} else {
			if !results.Successful() {
				msg := fmt.Sprintf("Feature '%s' not found on cluster '%s'", featureName, clusterName)
				if Verbose || Debug {
					msg += fmt.Sprintf(":\n%s", results.AllErrorMessages())
				}
				response.Succeeded(msg)
			} else {
				msg := fmt.Sprintf("Feature '%s' found on cluster '%s'\n", featureName, clusterName)
				response.Succeeded(msg)
			}
		}

		return response.GetErrorWithoutMessage()
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
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			return response.Failed(err)
		}
		err = extractFeatureArgument(c)
		if err != nil {
			return response.Failed(err)
		}
		feature, err := install.NewFeature(concurrency.RootTask(), featureName)
		if err != nil {
			return response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error()))
		}
		if feature == nil {
			msg := fmt.Sprintf("Failed to find a feature named '%s'.\n", featureName)
			return response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.NotFound, msg))
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

		target := install.NewClusterTarget(concurrency.RootTask(), clusterInstance)
		results, err := feature.Remove(target, values, settings)
		if err != nil {
			msg := fmt.Sprintf("Error uninstalling feature '%s' on '%s': %s\n", featureName, clusterName, err.Error())
			_ = response.Failed(clitools.ExitOnRPC(msg))
		}
		if !results.Successful() {
			msg := fmt.Sprintf("Failed to delete feature '%s' from cluster '%s'", featureName, clusterName)
			if Verbose || Debug {
				msg += fmt.Sprintf(":\n%s\n", results.AllErrorMessages())
			}
			_ = response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, msg))
		} else {
			response.Succeeded(nil)
		}

		return response.GetErrorWithoutMessage()
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

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> node <nodename> COMMAND
	//        {{.ProgName}} [options] cluster <clustername> node list|ls`,
	// 		Commands: `
	//   list|ls         Lists nodes in cluster
	//   inspect         Displays information about the node
	//   stop|freeze     Stops the node
	//   start|unfreeze  Delete a Cluster
	//   state           Returns current state of the node`,
	// 		Description: `
	// Deploy a new cluster <clustername> or something on the cluster <clustername>.`,
	// 		Footer: `
	// Run 'deploy cluster COMMAND --help' for more information on a command.`,
	// 	},
}

// clusterNodeListCommand handles 'deploy cluster node list CLUSTERNAME'
var clusterNodeListCommand = cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "list CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> node list|ls`,
	// 		Description: `
	// List nodes in the clusters.`,
	// 	},

	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			_ = response.Failed(err)
		} else {
			hostClt := client.New().Host
			formatted := []map[string]interface{}{}

			list := clusterInstance.ListNodeIDs(concurrency.RootTask())
			for _, i := range list {
				host, err := hostClt.Inspect(i, client.DefaultExecutionTimeout)
				if err != nil {
					msg := fmt.Sprintf("Failed to get data for node '%s': %s. Ignoring.", i, err.Error())
					//fmt.Println(msg)
					log.Warnln(msg)
					continue
				}
				formatted = append(formatted, map[string]interface{}{
					"name": host.Name,
				})
			}
			response.Succeeded(formatted)
		}

		return response.GetErrorWithoutMessage()
	},
}

// formatNodeConfig...
func formatNodeConfig(value interface{}) map[string]interface{} {
	core := value.(map[string]interface{})
	return core
}

// clusterNodeInspectCmd handles 'deploy cluster <clustername> inspect'
var clusterNodeInspectCommand = cli.Command{
	Name:      "inspect",
	Usage:     "node inspect CLUSTERNAME HOSTNAME",
	ArgsUsage: "CLUSTERNAME is the name of the cluster\nHOSTNAME is the hostname of the host resource inside the cluster (ie. for a cluster called 'demo', hostname is 'node-1' and host resourcename is 'demo-node-1')",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> node <hostname> inspect`,
	// 		Description: `
	// Displays information about the node <hostname> of cluster <clustername>.`,
	// 	},

	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			return response.Failed(err)
		}
		err = extractHostArgument(c, 1)
		if err != nil {
			return response.Failed(err)
		}

		host, err := client.New().Host.Inspect(hostName, client.DefaultExecutionTimeout)
		if err != nil {
			_ = response.Failed(clitools.ExitOnRPC(err.Error()))
		} else {
			response.Succeeded(host)
		}

		return response.GetErrorWithoutMessage()
	},
}

// clusterNodeDeleteCmd handles 'deploy cluster <clustername> delete'
var clusterNodeDeleteCommand = &cli.Command{
	Name:    "delete",
	Aliases: []string{"destroy", "remove", "rm"},

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> node <nodename> delete|destroy|remove|rm [-y]`,
	// 		Options: []string{`
	// options:
	//   -y,--assume-yes  Don't ask for confirmation`,
	// 		},
	// 		Description: `
	// Delete the node <nodename> from the cluster <clustername>.`,
	// 	},

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
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			return response.Failed(err)
		}
		err = extractHostArgument(c, 1)
		if err != nil {
			return response.Failed(err)
		}

		yes := c.Bool("yes")
		force := c.Bool("force")

		if !yes && !utils.UserConfirmed(fmt.Sprintf("Are you sure you want to delete the node '%s' of the cluster '%s'", hostName, clusterName)) {
			response.Succeeded("Aborted")
		} else {
			if force {
				log.Println("'-f,--force' does nothing yet")
			}

			err = clusterInstance.Delete(concurrency.RootTask())
			if err != nil {
				_ = response.Failed(clitools.ExitOnRPC(err.Error()))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

// clusterNodeStopCmd handles 'deploy cluster <clustername> node <nodename> stop'
var clusterNodeStopCommand = cli.Command{
	Name:    "stop",
	Aliases: []string{"freeze"},
	Usage:   "node stop CLUSTERNAME HOSTNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> stop|freeze`,
	// 		Description: `
	// Stop the cluster (make it unavailable for duty).`,
	// 	},

	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			return response.Failed(err)
		}
		err = extractHostArgument(c, 1)
		if err != nil {
			return response.Failed(err)
		}
		_ = response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.NotImplemented, "Not yet implemented"))

		return response.GetErrorWithoutMessage()
	},
}

// clusterNodeStartCmd handles 'deploy cluster <clustername> node <nodename> start'
var clusterNodeStartCommand = cli.Command{
	Name:    "start",
	Aliases: []string{"unfreeze"},
	Usage:   "node start CLUSTERNAME HOSTNAME",

	//Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> node <nodename> start|unfreeze`,
	// 		Options: []string{`
	// options:
	//   --force, -f Force Don't ask for confirmation`,
	// 		},
	// 		Description: `
	// Start the node <nodename> of the cluster <clustername>.`,
	// 	},

	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			return response.Failed(err)
		}
		err = extractHostArgument(c, 1)
		if err != nil {
			return response.Failed(err)
		}
		_ = response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.NotImplemented, "Not yet implemented"))

		return response.GetErrorWithoutMessage()
	},
}

// clusterNodeStateCmd handles 'deploy cluster <clustername> state'
var clusterNodeStateCommand = cli.Command{
	Name:  "state",
	Usage: "node state CLUSTERNAME HOSTNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> node <nodename> state`,
	// 		Description: `
	// Get the state of the node <nodename> of the cluster <clustername>.`,
	// 	},

	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			return response.Failed(err)
		}
		err = extractHostArgument(c, 1)
		if err != nil {
			return response.Failed(err)
		}
		_ = response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.NotImplemented, "Not yet implemented"))

		return response.GetErrorWithoutMessage()
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

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> node list|ls`,
	// 		Description: `
	// List nodes in the clusters.`,
	// 	},

	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		err := extractClusterArgument(c)
		if err != nil {
			_ = response.Failed(err)
		} else {
			hostClt := client.New().Host
			formatted := []map[string]interface{}{}

			list := clusterInstance.ListMasterIDs(concurrency.RootTask())
			for _, i := range list {
				host, err := hostClt.Inspect(i, client.DefaultExecutionTimeout)
				if err != nil {
					msg := fmt.Sprintf("Failed to get data for master '%s': %s. Ignoring.", i, err.Error())
					fmt.Println(msg)
					log.Warnln(msg)
					continue
				}
				formatted = append(formatted, map[string]interface{}{
					"name": host.Name,
					"id":   host.Id,
				})
			}
			response.Succeeded(formatted)
		}

		return response.GetErrorWithoutMessage()
	},
}
