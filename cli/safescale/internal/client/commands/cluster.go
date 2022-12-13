/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/spf13/cobra"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

var (
	clusterName string
	featureName string
	nodeName    string
	masterName  string
)

const (
	clusterCmdLabel        = "cluster"
	clusterFeatureCmdLabel = "feature"
)

func ClusterCommands() *cobra.Command {
	out := &cobra.Command{
		Use:     "cluster",
		Aliases: []string{"datacenter", "dc", "platform"},
		Short:   "create and manage cluster",
		// ArgsUsage: "COMMAND",
		PersistentPreRunE: func(c *cobra.Command, args []string) error {
			if c.Name() != clusterListCmdLabel {
				err := extractClusterName(c, args)
				if err != nil {
					return cli.FailureResponse(err)
				}
			}
			return nil
		},
	}
	out.AddCommand(
		clusterListCommand(),
		clusterCreateCommand(),
		clusterDeleteCommand(),
		clusterInspectCommand(),
		clusterStateCommand(),
		// clusterRunCommand(),
		clusterStartCommand(),
		clusterStopCommand(),
		clusterExpandCommand(),
		clusterShrinkCommand(),
		clusterKubectlCommand(),
		clusterHelmCommand(),
		clusterFeatureCommands(),
		clusterAnsibleCommands(),
		clusterFeatureCommands(),
		clusterMasterCommands(),
		clusterNodeCommands(),
	)
	addPersistentPreRunE(out)
	addCommonFlags(out)
	return out
}

// clusterListCommand handles 'deploy cluster list'
const clusterListCmdLabel = "list"

func clusterListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     clusterListCmdLabel,
		Aliases: []string{"ls"},
		Short:   "List available clusters",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			list, err := ClientSession.Cluster.List(temporal.ExecutionTimeout())
			if err != nil {
				err := fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "failed to get cluster list", false).Error())))
			}

			var formatted []interface{}
			for _, value := range list.Clusters {
				// c, _ := value.(api.Cluster)
				converted, xerr := convertToMap(value)
				if xerr != nil {
					return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, fail.Wrap(xerr, "failed to extract data about cluster '%s'", clusterName).Error()))
				}

				fconfig, xerr := formatClusterConfig(converted, false)
				if xerr != nil {
					return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, fail.Wrap(xerr, "failed to extract data about cluster '%s'", clusterName).Error()))
				}
				formatted = append(formatted, fconfig)
			}
			return cli.SuccessResponse(formatted)
		},
	}

	return out
}

// clusterInspectCommand handles 'deploy cluster <clustername> inspect'
func clusterInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show", "get"},
		Short:   "inspect CLUSTERNAME",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			cluster, err := ClientSession.Cluster.Inspect(clusterName, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.RPC, err.Error()))
			}

			clusterConfig, err := outputClusterConfig(cluster)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
			}
			return cli.SuccessResponse(clusterConfig)
		},
	}
	return out
}

// createCmd handles 'deploy cluster <clustername> create'
func clusterCreateCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "create",
		Aliases: []string{"new"},
		Short:   "create a cluster",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (err error) {
			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			complexityStr, err := c.Flags().GetString("complexity")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			comp, err := clustercomplexity.Parse(complexityStr)
			if err != nil {
				msg := fmt.Sprintf("Invalid option --complexity|-C: %s", err.Error())
				return cli.FailureResponse(cli.ExitOnInvalidOption(msg))
			}

			flavorStr, err := c.Flags().GetString("flavor")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			fla, err := clusterflavor.Parse(flavorStr)
			if err != nil {
				msg := fmt.Sprintf("Invalid option --flavor|-F: %s", err.Error())
				return cli.FailureResponse(cli.ExitOnInvalidOption(msg))
			}

			force, err := c.Flags().GetBool("force")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			keep, err := c.Flags().GetBool("keep-on-failure")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			cidr, err := c.Flags().GetString("cidr")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			disable, err := c.Flags().GetStringSlice("disable")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			los, err := c.Flags().GetString("os")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			gatewaySSHPort, err := c.Flags().GetUint32("gwport")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			parameters, err := c.Flags().GetStringSlice("param")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			var (
				globalDef   string
				gatewaysDef string
				mastersDef  string
				nodesDef    string
			)
			if c.Flags().Lookup("sizing") != nil {
				globalDef, err = constructHostDefinitionStringFromCLI(c, "sizing")
				if err != nil {
					return err
				}
			}
			if c.Flags().Lookup("gw-sizing") != nil {
				gatewaysDef, err = constructHostDefinitionStringFromCLI(c, "gw-sizing")
				if err != nil {
					return err
				}
			}
			if c.Flags().Lookup("master-sizing") != nil {
				mastersDef, err = constructHostDefinitionStringFromCLI(c, "master-sizing")
				if err != nil {
					return err
				}
			}
			if c.Flags().Lookup("node-sizing") != nil {
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
				Parameters:     parameters,
				DefaultSshPort: gatewaySSHPort,
			}
			res, err := ClientSession.Cluster.Create(&req, temporal.HostLongOperationTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
			}
			if res == nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, "failed to create cluster: unknown reason"))
			}

			toFormat, cerr := convertToMap(res)
			if cerr != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, cerr.Error()))
			}

			formatted, cerr := formatClusterConfig(toFormat, true)
			if cerr != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, cerr.Error()))
			}

			if !global.Settings.Debug {
				delete(formatted, "defaults")
			}
			return cli.SuccessResponse(formatted)
		},
	}

	flags := out.Flags()
	flags.StringP("complexity", "C", "Small", `Defines the sizing of the cluster: Small, Normal, Large
	Default number of machines (#master, #nodes) depending of flavor are:
		BOH: Small(1,1), Normal(3,3), Large(5,6)
		K8S: Small(1,1), Normal(3,3), Large(5,6)`)
	flags.StringP("flavor", "F", "K8S", `Defines the type of the cluster; can be BOH, K8S
	Default sizing for each cluster type is:
		BOH: gws(cpu=[2-4], ram=[7-16], disk=[50]), masters(cpu=[4-8], ram=[15-32], disk=[100]), nodes(cpu=[2-4], ram=[15-32], disk=[80])
		K8S: gws(cpu=[2-4], ram=[7-16], disk=[50]), masters(cpu=[4-8], ram=[15-32], disk=[100]), nodes(cpu=[4-8], ram=[15-32], disk=[80])`)
	flags.BoolP("keep-on-failure", "k", false, "If used, the resources are not deleted on failure (default: not set)")
	flags.BoolP("force", "f", false, "If used, it forces the cluster creation even if requested sizing is less than recommended")
	flags.Uint32("gwport", 22, `Define the port to use for SSH (default: 22) in gateways`)
	flags.Uint32("default-ssh-port", 22, "Alias of --gwport")
	flags.StringP("cidr", "N", stacks.DefaultNetworkCIDR, "Defines the CIDR of the network to use with cluster")
	flags.String("domain", "cluster.local", "domain name of the hosts in the cluster (default: cluster.local)")
	flags.StringSlice("disable", nil, "Allows to disable addition of default features (can be used several times to disable several features)")
	flags.String("os", "", "Defines the operating system to use")
	flags.String("sizing", "", `Describe sizing for any type of host in format "<component><operator><value>[,...]" where:
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
		- <template> is expecting the name of a template from Cloud provider; if template is not found, fallback to other components defined
	examples:
		--sizing "cpu <= 4, ram <= 10, disk = 100"
		--sizing "cpu ~ 4, ram = [14-32]" (is identical to --sizing "cpu=[4-8], ram=[14-32]")
		--sizing "cpu <= 8, ram ~ 16"
		--sizing "template=x1.large"
	Can be used with --gw-sizing and friends to set a global host sizing and refine for a particular type of host.`)
	flags.String("gw-sizing", "", `Describe gateway sizing in format "<component><operator><value>[,...] (cf. --sizing for details)`)
	flags.String("master-sizing", "", `Describe master sizing in format "<component><operator><value>[,...]" (cf. --sizing for details)`)
	flags.String("node-sizing", "", `Describe node sizing in format "<component><operator><value>[,...]" (cf. --sizing for details),
		This parameter accepts a supplemental <component> named count, with only = as <operator> and an int as <value> corresponding to the
		number of workers to create (cannot be less than the minimum required by the flavor).
	example:
		--node-sizing "cpu~4, ram~15, count=8" will create 8 nodes`)
	flags.StringSliceP("param", "p", nil, "Allow to define parameter values for automatically installed Features (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)")

	return out
}

// deleteCmd handles 'deploy cluster <clustername> delete'
func clusterDeleteCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"destroy", "remove", "rm"},
		Short:   "delete CLUSTERNAME",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			yes, err := c.Flags().GetBool("assume-yes")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			force, err := c.Flags().GetBool("force")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			if !yes && !utils.UserConfirmed(fmt.Sprintf("Are you sure you want to delete Cluster '%s'", clusterName)) {
				return cli.SuccessResponse("Aborted")
			}

			err = ClientSession.Cluster.Delete(clusterName, force, temporal.HostLongOperationTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}
			return cli.SuccessResponse(nil)
		},
	}

	flags := out.Flags()
	flags.BoolP("yes", "y", false, "do not ask confirmation")
	flags.Bool("assume-yes", false, "alias of --yes|-y")
	_ = flags.MarkDeprecated("assume-yes", "DEPRECATED")
	flags.BoolP("force", "f", false, "force action")

	return out
}

// clusterStopCmd handles 'deploy cluster <clustername> stop'
func clusterStopCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "stop",
		Aliases: []string{"freeze", "halt"},
		Short:   "stop CLUSTERNAME",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			err := ClientSession.Cluster.Stop(clusterName, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}

			return cli.SuccessResponse(nil)
		},
	}
	return out
}

func clusterStartCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "start",
		Aliases: []string{"unfreeze"},
		Short:   "start CLUSTERNAME",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			err := ClientSession.Cluster.Start(clusterName, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "start of cluster", false).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}
	return out
}

// clusterStateCmd handles 'deploy cluster <clustername> state'
func clusterStateCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "state",
		Short: "state CLUSTERNAME",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			state, err := ClientSession.Cluster.GetState(clusterName, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				msg := fmt.Sprintf("failed to get cluster state: %s", err.Error())
				return cli.FailureResponse(cli.ExitOnRPC(msg))
			}

			return cli.SuccessResponse(map[string]interface{}{
				"Name":       clusterName,
				"State":      state.State,
				"StateLabel": clusterstate.Enum(state.State).String(),
			})
		},
	}
	return out
}

// clusterExpandCmd handles 'deploy cluster <clustername> expand'
func clusterExpandCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "expand",
		Short: "expand CLUSTERNAME",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			count, err := c.Flags().GetUint("count")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			if count == 0 {
				count = 1
			}

			los, err := c.Flags().GetString("os")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			keepOnFailure, err := c.Flags().GetBool("keep-on-failure")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			parameters, err := c.Flags().GetStringSlice("param")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			var (
				nodesDef   string
				nodesCount uint
			)
			nodesDef, xerr := constructHostDefinitionStringFromCLI(c, "node-sizing")
			if xerr != nil {
				return xerr
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
				Parameters:    parameters,
			}

			hosts, err := ClientSession.Cluster.Expand(&req, temporal.HostLongOperationTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}

			return cli.SuccessResponse(hosts)
		},
	}

	flags := out.Flags()
	flags.UintP("count", "n", 1, "Define the number of nodes wanted (default: 1)")
	flags.String("os", "", "Define the Operating System wanted")
	flags.String("node-sizing", "", `Describe node sizing in format "<component><operator><value>[,...]" where:
	<component> can be cpu, cpufreq, gpu, ram, disk, os
	<operator> can be =,<,> (except for disk where valid operators are only = or >)
	<value> can be an integer (for cpu and disk) or a float (for ram) or an including interval "[<lower value>-<upper value>]"`)
	flags.BoolP("keep-on-failure", "k", false, `do not delete resources on failure`)
	flags.StringSliceP("param", "p", nil, "Allow to define parameter values for automatically installed Features (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)")

	return out
}

// clusterShrinkCommand handles 'deploy cluster <clustername> shrink'
func clusterShrinkCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "shrink",
		Short: "shrink CLUSTERNAME",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			count, err := c.Flags().GetUint("count")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			yes, err := c.Flags().GetBool("yes")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			var countS string
			if count > 1 {
				countS = "s"
			}

			if !yes {
				msg := fmt.Sprintf("Are you sure you want to delete %d node%s from Cluster %s", count, countS, clusterName)
				if !utils.UserConfirmed(msg) {
					return cli.SuccessResponse("Aborted")
				}
			}

			req := protocol.ClusterResizeRequest{
				Name:  clusterName,
				Count: int32(count),
			}

			if _, err := ClientSession.Cluster.Shrink(&req, temporal.HostLongOperationTimeout()); err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}

			return cli.SuccessResponse(nil)
		},
	}

	flags := out.Flags()
	flags.IntP("count", "n", 1, "Define the number of nodes to remove (default: 1)")
	flags.BoolP("yes", "y", false, "Do not ask confirmation")
	flags.Bool("assume-yes", false, "Alias of --yes|-y")
	_ = flags.MarkDeprecated("assume-yes", "DEPRECATED")

	return out
}

func clusterKubectlCommand() *cobra.Command {
	out := &cobra.Command{
		Use: "kubectl",
		// Category:  "Administrative commands",
		Short: "kubectl CLUSTERNAME [KUBECTL_COMMAND]... [-- [KUBECTL_OPTIONS]...]",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			clientID := GenerateClientIdentity()
			args = args[1:]
			var filteredArgs []string
			ignoreNext := false
			valuesOnRemote := &cmdline.RemoteFilesHandler{}
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
								return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
							}
							// If it's a link, get the target of it
							if st.Mode()&os.ModeSymlink == os.ModeSymlink {
								link, err := filepath.EvalSymlinks(localFile)
								if err != nil {
									return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
								}

								_, err = os.Stat(link)
								if err != nil {
									return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
								}
							}

							if localFile != "-" {
								rfi := cmdline.RemoteFileItem{
									Local:  localFile,
									Remote: fmt.Sprintf("%s/kubectl_values_%d.%s.%d.tmp", utils.TempFolder, idx+1, clientID, time.Now().UnixNano()),
								}
								valuesOnRemote.Add(&rfi)
								filteredArgs = append(filteredArgs, "-f")
								filteredArgs = append(filteredArgs, rfi.Remote)
							} else {
								// data comes from the standard input
								return cli.FailureResponse(fmt.Errorf("'-f -' is not yet supported"))
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

			return executeCommand(cmdStr, valuesOnRemote, outputs.DISPLAY)
		},
	}
	return out
}

func clusterHelmCommand() *cobra.Command {
	out := &cobra.Command{
		Use: "helm",
		// Category:  "Administrative commands",
		Short: "helm CLUSTERNAME COMMAND [[--][PARAMS ...]]",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			clientID := GenerateClientIdentity()
			// useTLS := " --tls"
			var filteredArgs []string
			args = args[1:]
			ignoreNext := false
			urlRegex := regexp.MustCompile("^(http|ftp)[s]?://")
			valuesOnRemote := &cmdline.RemoteFilesHandler{}
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
						return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.InvalidArgument, fmt.Sprintf("helm init is forbidden")))
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
								return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
							}

							// If it's a link, get the target of it
							if st.Mode()&os.ModeSymlink == os.ModeSymlink {
								link, err := filepath.EvalSymlinks(localFile)
								if err != nil {
									return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
								}

								_, err = os.Stat(link)
								if err != nil {
									return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
								}
							}

							if localFile != "-" {
								rfc := cmdline.RemoteFileItem{
									Local:  localFile,
									Remote: fmt.Sprintf("%s/helm_values_%d.%s.%d.tmp", utils.TempFolder, idx+1, clientID, time.Now().UnixNano()),
								}
								valuesOnRemote.Add(&rfc)
								filteredArgs = append(filteredArgs, "-f")
								filteredArgs = append(filteredArgs, rfc.Remote)
							} else {
								// data comes from the standard input
								return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.NotImplemented, "'-f -' is not yet supported"))
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

			return executeCommand(cmdStr, valuesOnRemote, outputs.DISPLAY)
		},
	}
	return out
}

// clusterRunCommand handles 'safescale cluster run'
// FIXME: not implemented
func clusterRunCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "run",
		Aliases: []string{"execute", "exec"},
		Short:   "run CLUSTERNAME COMMAND",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.NotImplemented, "runCmd not yet implemented"))
		},
	}
	return out
}

// clusterFeatureCommands handle 'safescale cluster feature'
func clusterFeatureCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   clusterFeatureCmdLabel,
		Short: "create and manage features on a cluster",
		// ArgsUsage: "COMMAND",
		PersistentPreRunE: func(c *cobra.Command, args []string) (err error) {
			if c.Name() != clusterFeatureListCmdLabel {
				featureName, err = extractFeatureArgument(c, args)
				if err != nil {
					return cli.FailureResponse(err)
				}
			}
			return nil
		},
	}
	out.AddCommand(
		clusterFeatureListCommand(),
		clusterFeatureInspectCommand(),
		clusterFeatureExportCommand(),
		clusterFeatureCheckCommand(),
		clusterFeatureAddCommand(),
		clusterFeatureRemoveCommand(),
	)
	return out
}

// clusterFeatureListCommand handles 'safescale cluster feature list <cluster name or id>'
const clusterFeatureListCmdLabel = "list"

func clusterFeatureListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     clusterFeatureListCmdLabel,
		Aliases: []string{"ls"},
		Short:   "List features installed on the cluster",
		// ArgsUsage: "",

		RunE: clusterFeatureListAction,
	}

	out.Flags().BoolP("all", "a", false, "if used, list all features that are eligible to be installed on the cluster")

	return out
}

// clusterFeatureInspectCommand handles 'safescale cluster feature inspect <cluster name or id> <feature name>'
// Displays information about the feature (parameters, if eligible on cluster, if installed, ...)
func clusterFeatureInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show"},
		Short:   "Inspects the feature",
		// ArgsUsage: "",

		RunE: clusterFeatureInspectAction,
	}

	out.Flags().Bool("embedded", false, "if used, tells to show details of embedded feature (if it exists)")

	return out
}

// clusterFeatureExportCommand handles 'safescale cluster feature export <cluster name or id> <feature name>'
func clusterFeatureExportCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "export",
		Aliases: []string{"ls"},
		Short:   "export a Feature",
		// ArgsUsage: "",
		RunE: clusterFeatureExportAction,
	}

	flags := out.Flags()
	flags.Bool("embedded", false, "if used, tells to export embedded feature (if it exists)")
	flags.Bool("raw", false, "outputs only the feature content, without json")

	return out
}

func clusterFeatureAddCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "add",
		Aliases: []string{"install"},
		Short:   "Installs a feature on a cluster",
		// ArgsUsage: "CLUSTERNAME FEATURENAME",
		RunE: clusterFeatureAddAction,
	}

	flags := out.Flags()
	flags.StringSliceP("param", "p", nil, "Define value of feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)")
	flags.Bool("skip-proxy", false, "Disables reverse proxy rules")

	return out
}

// clusterFeatureCheckCommand handles 'deploy cluster check-feature CLUSTERNAME FEATURENAME'
func clusterFeatureCheckCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "check",
		Aliases: []string{"verify"},
		Short:   "Checks if a Feature is already installed on cluster",
		// ArgsUsage: "CLUSTERNAME FEATURENAME",
		RunE: clusterFeatureCheckAction,
	}

	out.Flags().StringSliceP("param", "p", nil, "Allow to define content of feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)")

	return out
}

// clusterFeatureRemoveCommand handles 'safescale cluster feature remove <cluster name> <pkgname>'
func clusterFeatureRemoveCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "remove",
		Aliases: []string{"destroy", "delete", "rm", "uninstall"},
		Short:   "Remove a feature from a cluster",
		// ArgsUsage: "CLUSTERNAME FEATURENAME",
		RunE: clusterFeatureRemoveAction,
	}

	out.Flags().StringSliceP("param", "p", nil, "Allow to define content of feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)")

	return out
}

func clusterFeatureListAction(c *cobra.Command, args []string) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Use, strings.Join(args, ", "))

	all, err := c.Flags().GetBool("all")
	if err != nil {
		return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
	}

	features, err := ClientSession.Cluster.ListFeatures(clusterName, all, 0) // FIXME: set timeout
	if err != nil {
		err = fail.FromGRPCStatus(err)
		return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
	}

	return cli.SuccessResponse(features)
}

func clusterFeatureInspectAction(c *cobra.Command, args []string) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, clusterFeatureCmdLabel, strings.Join(args, ", "))

	embedded, err := c.Flags().GetBool("all")
	if err != nil {
		return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
	}

	details, err := ClientSession.Cluster.InspectFeature(clusterName, featureName, embedded, 0) // FIXME: set timeout
	if err != nil {
		err = fail.FromGRPCStatus(err)
		return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
	}

	return cli.SuccessResponse(details)
}

func clusterFeatureExportAction(c *cobra.Command, args []string) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, clusterFeatureCmdLabel, strings.Join(args, ", "))

	embedded, err := c.Flags().GetBool("embedded")
	if err != nil {
		return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
	}

	export, err := ClientSession.Cluster.ExportFeature(clusterName, featureName, embedded, 0) // FIXME: set timeout
	if err != nil {
		err = fail.FromGRPCStatus(err)
		return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
	}

	raw, err := c.Flags().GetBool("raw")
	if err != nil {
		return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
	}

	if raw {
		return cli.SuccessResponse(export.Export)
	}

	return cli.SuccessResponse(export)
}

func clusterFeatureAddAction(c *cobra.Command, args []string) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterFeatureCmdLabel, c.Name(), strings.Join(args, ", "))

	parameters, err := c.Flags().GetStringSlice("param")
	if err != nil {
		return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
	}

	values := parametersToMap(parameters)

	settings := protocol.FeatureSettings{}
	settings.SkipProxy, err = c.Flags().GetBool("skip-proxy")
	if err != nil {
		return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
	}

	if err := ClientSession.Cluster.AddFeature(clusterName, featureName, values, &settings, 0); err != nil {
		err = fail.FromGRPCStatus(err)
		msg := fmt.Sprintf("error adding feature '%s' on cluster '%s': %s", featureName, clusterName, err.Error())
		return cli.FailureResponse(cli.ExitOnRPC(msg))
	}
	return cli.SuccessResponse(nil)
}

func clusterFeatureCheckAction(c *cobra.Command, args []string) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterFeatureCmdLabel, c.Name(), strings.Join(args, ", "))

	parameters, err := c.Flags().GetStringSlice("param")
	if err != nil {
		return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
	}

	values := parametersToMap(parameters)
	settings := protocol.FeatureSettings{}

	err = ClientSession.Cluster.CheckFeature(clusterName, featureName, values, &settings, 0)
	if err != nil { // FIXME: define duration
		err = fail.FromGRPCStatus(err)
		msg := fmt.Sprintf("error checking Feature '%s' on Cluster '%s': %s", featureName, clusterName, err.Error())
		return cli.FailureResponse(cli.ExitOnRPC(msg))
	}

	msg := fmt.Sprintf("Feature '%s' found on cluster '%s'", featureName, clusterName)
	return cli.SuccessResponse(msg)
}

func clusterFeatureRemoveAction(c *cobra.Command, args []string) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterFeatureCmdLabel, c.Name(), strings.Join(args, ", "))

	parameters, err := c.Flags().GetStringSlice("param")
	if err != nil {
		return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
	}

	values := parametersToMap(parameters)
	settings := protocol.FeatureSettings{}
	// TODO: Reverse proxy rules are not yet purged when feature is removed, but current code
	//       will try to apply them... Quick fix: Setting SkipProxy to true prevent this
	settings.SkipProxy = true

	if err := ClientSession.Cluster.RemoveFeature(clusterName, featureName, values, &settings, 0); err != nil {
		err = fail.FromGRPCStatus(err)
		msg := fmt.Sprintf("failed to remove Feature '%s' on Cluster '%s': %s", featureName, clusterName, err.Error())
		return cli.FailureResponse(cli.ExitOnRPC(msg))
	}

	return cli.SuccessResponse(nil)
}

// clusterNodeCommands handles 'safescale cluster node' commands
const clusterNodeCmdLabel = "node"

func clusterNodeCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   clusterNodeCmdLabel,
		Short: "manage cluster nodes",
		// ArgsUsage: "COMMAND",
		PersistentPreRunE: func(c *cobra.Command, args []string) (err error) {
			if c.Name() != clusterNodeListCmdLabel {
				nodeName, err = extractNodeArgument(args)
				if err != nil {
					return cli.FailureResponse(err)
				}
			}
			return nil
		},
	}
	out.AddCommand(
		clusterNodeListCommand(),
		clusterNodeInspectCommand(),
		clusterNodeStartCommand(),
		clusterNodeStopCommand(),
		clusterNodeStateCommand(),
		clusterNodeDeleteCommand(),
	)
	return out
}

// clusterNodeListCommand handles 'deploy cluster node list CLUSTERNAME'
const clusterNodeListCmdLabel = "list"

func clusterNodeListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     clusterNodeListCmdLabel,
		Aliases: []string{"ls"},
		Short:   "Lists the nodes of a cluster",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Name(), strings.Join(args, ", "))

			var formatted []map[string]interface{}

			list, err := ClientSession.Cluster.ListNodes(clusterName, 0)
			if err != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
			}

			for _, host := range list.Nodes {
				formatted = append(formatted, map[string]interface{}{
					"name": host.GetName(),
					"id":   host.GetId(),
				})
			}
			return cli.SuccessResponse(formatted)
		},
	}
	return out
}

// clusterNodeInspectCmd handles 'deploy cluster <clustername> inspect'
func clusterNodeInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "inspect",
		Short: "Show details about a cluster node",
		// ArgsUsage: "CLUSTERNAME HOSTNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Name(), strings.Join(args, ", "))

			host, err := ClientSession.Cluster.InspectNode(clusterName, nodeName, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}
			return cli.SuccessResponse(host)
		},
	}
	return out
}

// clusterNodeDeleteCmd handles 'deploy cluster <clustername> delete'
func clusterNodeDeleteCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"destroy", "remove", "rm"},

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Use, strings.Join(args, ", "))

			nodeList := args[1:]
			yes, err := c.Flags().GetBool("yes")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			force, err := c.Flags().GetBool("force")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnInvalidOption(err.Error()))
			}

			_, err = ClientSession.Cluster.Inspect(clusterName, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.RPC, err.Error()))
			}

			if len(nodeList) == 0 {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.InvalidArgument, "missing nodes"))
			}

			if !yes && !utils.UserConfirmed(fmt.Sprintf("Are you sure you want to delete the node%s '%s' of the cluster '%s'", strprocess.Plural(uint(len(nodeList))), strings.Join(nodeList, ","), clusterName)) {
				return cli.SuccessResponse("Aborted")
			}
			if force {
				logrus.Println("'-f,--force' does nothing yet")
			}

			err = ClientSession.Cluster.DeleteNode(clusterName, nodeList, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}

			return cli.SuccessResponse(nil)
		},
	}

	flags := out.Flags()
	flags.BoolP("yes", "y", false, "If set, respond automatically yes to all questions")
	flags.BoolP("force", "f", false, "If set, force node deletion no matter what (ie. metadata inconsistency)")

	return out
}

// clusterNodeStopCmd handles 'deploy cluster <clustername> node <nodename> stop'
func clusterNodeStopCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "stop",
		Aliases: []string{"freeze"},
		Short:   "node stop CLUSTERNAME HOSTNAME",
		// ArgsUsage: "CLUSTERNAME HOSTNAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Name(), strings.Join(args, ", "))

			err := ClientSession.Cluster.StopNode(clusterName, nodeName, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}

			return cli.SuccessResponse(nil)
		},
	}
	return out
}

// clusterNodeStartCmd handles 'deploy cluster <clustername> node <nodename> start'
func clusterNodeStartCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "start",
		Aliases: []string{"unfreeze"},
		Short:   "node start CLUSTERNAME HOSTNAME",
		// ArgsUsage: "CLUSTERNAME NODENAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Name(), strings.Join(args, ", "))

			err := ClientSession.Cluster.StartNode(clusterName, nodeName, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}

			return cli.SuccessResponse(nil)
		},
	}
	return out
}

// clusterNodeStateCmd handles 'deploy cluster <clustername> state'
func clusterNodeStateCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "state",
		Short: "node state CLUSTERNAME HOSTNAME",
		// ArgsUsage: "CLUSTERNAME NODENAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterNodeCmdLabel, c.Name(), strings.Join(args, ", "))

			resp, err := ClientSession.Cluster.StateNode(clusterName, nodeName, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}

			formatted := make(map[string]interface{})
			formatted["name"] = resp.Name
			converted := converters.HostStateFromProtocolToEnum(resp.Status)
			formatted["status_code"] = converted
			formatted["status_label"] = converted.String()
			return cli.SuccessResponse(formatted)
		},
	}
	return out
}

const clusterMasterCmdLabel = "master"

// clusterMasterCommands handles 'safescale cluster master ...
func clusterMasterCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   clusterMasterCmdLabel,
		Short: "manage cluster masters",
		// ArgsUsage: "COMMAND",
		PersistentPreRunE: func(c *cobra.Command, args []string) (err error) {
			if c.Name() != clusterMasterListCmdLabel {
				masterName, err = extractNodeArgument(args)
				if err != nil {
					return cli.FailureResponse(err)
				}
			}
			return nil
		},
	}
	out.AddCommand(
		clusterMasterListCommand(),
		clusterMasterInspectCommand(),
		clusterMasterStateCommand(),
		clusterMasterStartCommand(),
		clusterMasterStopCommand(),
	)
	return out
}

// clusterMasterListCommand handles 'safescale cluster master list CLUSTERNAME'
const clusterMasterListCmdLabel = "list"

func clusterMasterListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     clusterMasterListCmdLabel,
		Aliases: []string{"ls"},
		Short:   "list CLUSTERNAME",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Name(), strings.Join(args, ", "))

			var formatted []map[string]interface{}

			list, err := ClientSession.Cluster.ListMasters(clusterName, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}

			for _, host := range list.Nodes {
				formatted = append(formatted, map[string]interface{}{
					"name": host.GetName(),
					"id":   host.GetId(),
				})
			}
			return cli.SuccessResponse(formatted)
		},
	}
	return out
}

// clusterMasterInspectCmd handles 'cluster master inspect <clustername> <masterref>'
func clusterMasterInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "inspect",
		Short: "Show details about a Cluster master",
		// ArgsUsage: "CLUSTERNAME MASTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Name(), strings.Join(args, ", "))

			host, err := ClientSession.Cluster.InspectNode(clusterName, masterName, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}

			return cli.SuccessResponse(host)
		},
	}
	return out
}

// clusterMasterStopCmd handles 'safescale cluster master stop <clustername> <mastername>'
func clusterMasterStopCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "stop",
		Aliases: []string{"freeze"},
		Short:   "master stop CLUSTERNAME MASTERNAME",
		// ArgsUsage: "CLUSTERNAME MASTERNAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Name(), strings.Join(args, ", "))

			err := ClientSession.Cluster.StopMaster(clusterName, masterName, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}

			return cli.SuccessResponse(nil)
		},
	}
	return out
}

// clusterMasterStartCmd handles 'deploy cluster <clustername> node <nodename> start'
func clusterMasterStartCommand() *cobra.Command {
	out := &cobra.Command{ // nolint
		Use:     "start",
		Aliases: []string{"unfreeze"},
		Short:   "master start CLUSTERNAME MASTERNAME",
		// ArgsUsage: "CLUSTERNAME MASTERNAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Name(), strings.Join(args, ", "))

			err := ClientSession.Cluster.StartMaster(clusterName, masterName, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}

			return cli.SuccessResponse(nil)
		},
	}
	return out
}

// clusterMasterNodeStateCmd handles 'safescale cluster master state <clustername> <mastername>'
func clusterMasterStateCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "state",
		Short: "master state CLUSTERNAME MASTERNAME",
		// ArgsUsage: "CLUSTERNAME MASTERNAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", clusterCmdLabel, clusterMasterCmdLabel, c.Name(), strings.Join(args, ", "))

			resp, err := ClientSession.Cluster.StateMaster(clusterName, masterName, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}

			formatted := make(map[string]interface{})
			formatted["name"] = resp.Name
			converted := converters.HostStateFromProtocolToEnum(resp.Status)
			formatted["status_code"] = converted
			formatted["status_label"] = converted.String()
			return cli.SuccessResponse(formatted)
		},
	}
	return out
}

func clusterAnsibleCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   "ansible",
		Short: "Administrative commands",
		// ArgsUsage: "COMMAND",
	}
	out.AddCommand(
		clusterAnsibleInventoryCommand(),
		clusterAnsibleRunCommand(),
		clusterAnsiblePlaybookCommand(),
	)
	return out
}

func clusterAnsibleInventoryCommand() *cobra.Command {
	out := &cobra.Command{
		Use: "inventory",
		// Category:  "Administrative commands",
		Short: "inventory CLUSTERNAME COMMAND [[--][PARAMS ...]]",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			// Set client session
			// Get cluster master
			master, err := ClientSession.Cluster.FindAvailableMaster(clusterName, 0) // FIXME: set duration
			if err != nil {
				msg := fmt.Sprintf("No masters found available for the cluster '%s': %v", clusterName, err.Error())
				return cli.ExitOnErrorWithMessage(exitcode.RPC, msg)
			}

			// Check for feature
			values := map[string]string{}
			settings := protocol.FeatureSettings{}
			if err := ClientSession.Cluster.CheckFeature(clusterName, "ansible", values, &settings, 0); err != nil { // FIXME: define duration
				err = fail.FromGRPCStatus(err)
				msg := fmt.Sprintf("error checking Feature 'ansible' on Cluster '%s': %s", clusterName, err.Error())
				return cli.FailureResponse(cli.ExitOnRPC(msg))
			}

			// Format arguments
			args = args[1:]
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
				case "--inventory-file": // Deprecated
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

			// Make command line
			cmdStr := `sudo -u cladm -i ansible-inventory -i ` + inventoryPath + ` ` + strings.Join(filteredArgs, " ") // + useTLS
			logrus.Tracef(cmdStr)
			retcode, _ /*stdout*/, stderr, xerr := ClientSession.SSH.Run(master.GetId(), cmdStr, outputs.DISPLAY, temporal.ConnectionTimeout(), temporal.ExecutionTimeout())
			if xerr != nil {
				msg := fmt.Sprintf("failed to execute command on master '%s' of cluster '%s': %s", master.GetName(), clusterName, xerr.Error())
				return cli.ExitOnErrorWithMessage(exitcode.RPC, msg)
			}
			if retcode != 0 {
				return cli.NewExitError(stderr, retcode)
			}
			return nil
		},
	}
	return out
}

func clusterAnsibleRunCommand() *cobra.Command {
	out := &cobra.Command{
		Use: "run",
		// Category:  "Administrative commands",
		Short: "run CLUSTERNAME COMMAND [[--][PARAMS ...]]",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			// Get cluster master
			master, err := ClientSession.Cluster.FindAvailableMaster(clusterName, 0) // FIXME: set duration
			if err != nil {
				msg := fmt.Sprintf("No masters found available for the cluster '%s': %v", clusterName, err.Error())
				return cli.ExitOnErrorWithMessage(exitcode.RPC, msg)
			}

			// Check for feature
			values := map[string]string{}
			settings := protocol.FeatureSettings{}
			if err := ClientSession.Cluster.CheckFeature(clusterName, "ansible", values, &settings, 0); err != nil { // FIXME: define duration
				err = fail.FromGRPCStatus(err)
				msg := fmt.Sprintf("error checking Feature 'ansible' on Cluster '%s': %s", clusterName, err.Error())
				return cli.FailureResponse(cli.ExitOnRPC(msg))
			}

			// Format arguments
			args = args[1:]
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
				case "--inventory-file": // Deprecated
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
			retcode, _ /*stdout*/, stderr, xerr := ClientSession.SSH.Run(master.GetId(), cmdStr, outputs.DISPLAY, temporal.ConnectionTimeout(), temporal.ExecutionTimeout())
			if xerr != nil {
				msg := fmt.Sprintf("failed to execute command on master '%s' of cluster '%s': %s", master.GetName(), clusterName, xerr.Error())
				return cli.ExitOnErrorWithMessage(exitcode.RPC, msg)
			}
			if retcode != 0 {
				return cli.NewExitError(stderr, retcode)
			}
			return nil
		},
	}
	return out
}

func clusterAnsiblePlaybookCommand() *cobra.Command {
	out := &cobra.Command{
		Use: "playbook",
		// Category:  "Administrative commands",
		Short: "playbook CLUSTERNAME COMMAND [[--][PARAMS ...]]",
		// ArgsUsage: "CLUSTERNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)

			logrus.Tracef("SafeScale command: %s %s with args '%s'", clusterCmdLabel, c.Name(), strings.Join(args, ", "))

			// Check for feature
			values := map[string]string{}
			settings := protocol.FeatureSettings{}
			if err := ClientSession.Cluster.CheckFeature(clusterName, "ansible", values, &settings, 0); err != nil { // FIXME: define duration
				err = fail.FromGRPCStatus(err)
				msg := fmt.Sprintf("error checking Feature 'ansible' on Cluster '%s': %s", clusterName, err.Error())
				return cli.FailureResponse(cli.ExitOnRPC(msg))
			}

			// Format arguments
			var (
				captureInventory    = false
				capturePlaybookFile = true
				filteredArgs        []string
				isParam             bool
			)
			// FIXME: Must set absolute inventory path, use "sudo -i" (interactive) with debian change $PATH, and makes fail ansible path finder (dirty way)
			// event not ~.ansible.cfg or ANSIBLE_CONFIG defined for user cladm (could be a solution ?)
			// find no configuration for playbook default directory, must be absolute (arg: local file, mapped to remote)
			inventoryPath := utils.BaseFolder + "/etc/ansible/inventory/inventory.py"
			playbookFile := ""
			args = args[1:]
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
				switch arg {
				case "-i":
				case "--inventory":
				case "--inventory-file": // Deprecated
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

				if !isParam && !capturePlaybookFile {
					capturePlaybookFile = true
				}
			}

			// Must set playbook file
			if playbookFile == "" {
				msg := fmt.Sprintf("Expect a playbook file for cluster '%s'", clusterName)
				return cli.ExitOnErrorWithMessage(exitcode.RPC, msg)
			}

			// Check local file exists
			if _, err := os.Stat(playbookFile); err != nil {
				if os.IsNotExist(err) {
					msg := fmt.Sprintf("Playbook file not found for cluster '%s'", clusterName)
					return cli.ExitOnErrorWithMessage(exitcode.RPC, msg)
				}
			}

			// Prepare remote playbook
			playbookBasename := playbookFile
			pos := strings.LastIndex(playbookFile, "/")
			if pos >= 0 {
				playbookBasename = playbookFile[pos+1:]
			}
			valuesOnRemote := &cmdline.RemoteFilesHandler{}
			rfc := cmdline.RemoteFileItem{
				Local:  playbookFile,
				Remote: fmt.Sprintf("%s/ansible_playbook.%s", utils.TempFolder, playbookBasename),
			}
			valuesOnRemote.Add(&rfc)

			// Run playbook
			cmdStr := `sudo chown cladm:root ` + rfc.Remote + ` && sudo chmod 0774 ` + rfc.Remote + ` && sudo -u cladm -i ansible-playbook ` + rfc.Remote + ` -i ` + inventoryPath + ` ` + strings.Join(filteredArgs, " ") // + useTLS
			return executeCommand(cmdStr, valuesOnRemote, outputs.DISPLAY)
		},
	}
	return out
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
		remotedesktopInstalled := true
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
			if ok { // FIXME: What if it fails ?, we should return an error too
				masters := nodes["masters"]
				if len(masters) > 0 {
					urls := make(map[string]string, len(masters))
					endpointIP, ok := config["endpoint_ip"].(string)
					if ok { // FIXME: What if it fails ?, we should return an error too
						for _, v := range masters {
							urls[v.Name] = fmt.Sprintf("https://%s/_platform/remotedesktop/%s/", endpointIP, v.Name)
						}
						config["remote_desktop"] = urls
					}
				}
			}
		} else {
			config["remote_desktop"] = fmt.Sprintf("no remote desktop available; to install on all masters, run 'safescale cluster feature add %s remotedesktop'", config["name"].(string))
		}
	}
	return config, nil
}

func executeCommand(command string, files *cmdline.RemoteFilesHandler, outs outputs.Enum) error {
	logrus.Debugf("command=[%s]", command)
	master, err := ClientSession.Cluster.FindAvailableMaster(clusterName, 0) // FIXME: set duration
	if err != nil {
		msg := fmt.Sprintf("No masters found available for the cluster '%s': %v", clusterName, err.Error())
		return cli.ExitOnErrorWithMessage(exitcode.RPC, msg)
	}

	if files != nil && files.Count() > 0 {
		if !global.Settings.Debug {
			defer files.Cleanup(ClientSession, master.GetId())
		}
		xerr := files.Upload(ClientSession, master.GetId())
		if xerr != nil {
			return cli.ExitOnErrorWithMessage(exitcode.RPC, xerr.Error())
		}
	}

	retcode, _, _, xerr := ClientSession.SSH.Run(master.GetId(), command, outs, temporal.ConnectionTimeout(), 0)
	if xerr != nil {
		msg := fmt.Sprintf("failed to execute command on master '%s' of cluster '%s': %s", master.GetName(), clusterName, xerr.Error())
		return cli.ExitOnErrorWithMessage(exitcode.RPC, msg)
	}
	if retcode != 0 {
		return cli.NewExitError("", retcode)
	}
	return nil
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

func extractClusterName(c *cobra.Command, args []string) (ferr error) {
	defer fail.OnPanic(&ferr)
	if len(args) < 1 {
		_ = c.Usage()
		return cli.ExitOnInvalidArgument("Missing mandatory argument CLUSTERNAME.")
	}
	clusterName = args[0]
	if clusterName == "" {
		_ = c.Usage()
		return cli.ExitOnInvalidArgument("Invalid argument CLUSTERNAME.")
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
