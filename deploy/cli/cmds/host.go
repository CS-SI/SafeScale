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

package cmds

import (
	"fmt"
	"log"
	"os"
	"strings"

	// log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"

	"github.com/CS-SI/SafeScale/utils/cli/ExitCode"

	"github.com/CS-SI/SafeScale/deploy/install"
)

var (
	hostName        string
	hostInstance    *pb.Host
	hostServiceName string
)

// HostCommand command
var HostCommand = cli.Command{
	Name:      "host",
	Usage:     "host",
	ArgsUsage: "COMMAND",
	Subcommands: []cli.Command{
		hostCheckFeatureCommand,
		hostAddFeatureCommand,
		hostDeleteFeatureCommand,
	},

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} host list|ls
	//        {{.ProgName}} [options] host <host name or id> COMMAND
	// `,
	// 		Commands: `
	//   feature  Manages SafeScale features
	//   service,svc  Manages operating system service`,
	// 		Description: `
	// Deploy package and service on a single host.`,
	// 		Footer: `
	// Run 'deploy host COMMAND --help' for more information on a command.`,
	// 	},

}

func extractHostArgument(c *cli.Context) error {
	if !c.Command.HasName("list") {
		if c.NArg() < 1 {
			msg := "Missing mandatory argument HOSTNAME"
			// _ = cli.ShowSubcommandHelp(c)
			return cli.NewExitError(msg, int(ExitCode.InvalidArgument))
		}
		hostName = c.Args().First()
		if hostName == "" {
			msg := "argument HOSTNAME invalid"
			return cli.NewExitError(msg, int(ExitCode.InvalidArgument))
		}

		var err error
		hostInstance, err = brokerclient.New().Host.Inspect(hostName, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			fmt.Printf("%s\n", err.Error())
			return cli.NewExitError(err.Error(), int(ExitCode.RPC))
		}
		if hostInstance == nil {
			return cli.NewExitError(fmt.Sprintf("Host '%s' not found.\n", clusterName), int(ExitCode.NotFound))
		}
	}
	return nil
}

// hostAddFeatureCommand handles 'deploy host <host name or id> package <pkgname> add'
var hostAddFeatureCommand = cli.Command{
	Name:      "add-feature",
	Aliases:   []string{"install-feature"},
	Usage:     "add-feature HOSTNAME FEATURENAME",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters",
		},
		cli.BoolFlag{
			Name:  "skip-proxy",
			Usage: "Disable reverse proxy rules",
		},
	},

	Action: func(c *cli.Context) error {
		err := extractHostArgument(c)
		if err != nil {
			return err
		}

		err = extractFeatureArgument(c)
		if err != nil {
			return err
		}

		feature, err := install.NewFeature(featureName)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(int(ExitCode.Run))
		}
		if feature == nil {
			fmt.Fprintf(os.Stderr, "Failed to find a feature named '%s'.\n", featureName)
			os.Exit(int(ExitCode.NotFound))
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

		// Wait for SSH service on remote host first
		err = brokerclient.New().Ssh.WaitReady(hostInstance.ID, brokerclient.DefaultConnectionTimeout)
		if err != nil {
			msg := fmt.Sprintf("Failed to reach '%s': %s", hostName, brokerclient.DecorateError(err, "waiting ssh on host", false))
			return cli.NewExitError(msg, int(ExitCode.RPC))
		}

		target := install.NewHostTarget(hostInstance)
		results, err := feature.Add(target, values, settings)
		if err != nil {
			msg := fmt.Sprintf("Error installing feature '%s' on host '%s': %s\n", featureName, hostName, err.Error())
			return cli.NewExitError(msg, int(ExitCode.RPC))
		}
		if !results.Successful() {
			msg := fmt.Sprintf("Failed to install feature '%s' on host '%s'\n%s", featureName, hostName, results.AllErrorMessages())
			return cli.NewExitError(msg, int(ExitCode.Run))
		}

		msg := fmt.Sprintf("Feature '%s' installed successfully on host '%s'\n", featureName, hostName)
		return cli.NewExitError(msg, int(ExitCode.OK))
	},
}

// hostCheckFeatureCommand handles 'deploy host <host name or id> package <pkgname> check'
var hostCheckFeatureCommand = cli.Command{
	Name:      "check-feature",
	Aliases:   []string{"verify-feature"},
	Usage:     "check-feature HOSTNAME FEATURENAME",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters",
		},
	},

	Action: func(c *cli.Context) error {
		err := extractHostArgument(c)
		if err != nil {
			return err
		}

		err = extractFeatureArgument(c)
		if err != nil {
			return err
		}

		feature, err := install.NewFeature(featureName)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(int(ExitCode.Run))
		}
		if feature == nil {
			fmt.Fprintf(os.Stderr, "Failed to find a feature named '%s'.\n", featureName)
			os.Exit(int(ExitCode.NotFound))
		}

		values := install.Variables{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		// Wait for SSH service on remote host first
		err = brokerclient.New().Ssh.WaitReady(hostInstance.ID, brokerclient.DefaultConnectionTimeout)
		if err != nil {
			msg := fmt.Sprintf("Failed to reach '%s': %s", hostName, brokerclient.DecorateError(err, "waiting ssh on host", false))
			return cli.NewExitError(msg, int(ExitCode.RPC))
		}

		target := install.NewHostTarget(hostInstance)
		results, err := feature.Check(target, values, install.Settings{})
		if err != nil {
			msg := fmt.Sprintf("Error checking if feature '%s' is installed on '%s': %s\n", featureName, hostName, err.Error())
			return cli.NewExitError(msg, int(ExitCode.RPC))
		}
		if !results.Successful() {
			fmt.Printf("Feature '%s' is not installed on '%s'\n", featureName, hostName)
			if Debug {
				log.Println(results.AllErrorMessages())
			}
			return cli.NewExitError("", int(ExitCode.NotFound))
		}

		fmt.Printf("Feature '%s' is installed on '%s'\n", featureName, hostName)
		return nil
	},
}

// hostDeleteFeatureCommand handles 'deploy host delete-feature <host name> <feature name>'
var hostDeleteFeatureCommand = cli.Command{
	Name:      "rm-feature",
	Aliases:   []string{"remove-feature", "delete-feature", "uninstall-feature"},
	Usage:     "Remove a feature from host.",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Define value of feature parameter (can be used multiple times)",
		},
	},

	Action: func(c *cli.Context) error {
		err := extractHostArgument(c)
		if err != nil {
			return err
		}

		err = extractFeatureArgument(c)
		if err != nil {
			return err
		}

		feature, err := install.NewFeature(featureName)
		if err != nil {
			return cli.NewExitError(err.Error(), int(ExitCode.Run))
		}
		if feature == nil {
			msg := fmt.Sprintf("Failed to find a feature named '%s'.\n", featureName)
			return cli.NewExitError(msg, int(ExitCode.NotFound))
		}

		values := install.Variables{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		// Wait for SSH service on remote host first
		err = brokerclient.New().Ssh.WaitReady(hostInstance.ID, brokerclient.DefaultConnectionTimeout)
		if err != nil {
			msg := fmt.Sprintf("Failed to reach '%s': %s", hostName, brokerclient.DecorateError(err, "waiting ssh on host", false))
			return cli.NewExitError(msg, int(ExitCode.RPC))
		}

		target := install.NewHostTarget(hostInstance)
		results, err := feature.Remove(target, values, install.Settings{})
		if err != nil {
			msg := fmt.Sprintf("Error uninstalling feature '%s' on '%s': %s\n", featureName, hostName, err.Error())
			return cli.NewExitError(msg, int(ExitCode.RPC))
		}
		if !results.Successful() {
			msg := fmt.Sprintf("Failed to delete feature '%s' from host '%s':\n%s", featureName, hostName, results.AllErrorMessages())
			return cli.NewExitError(msg, int(ExitCode.Run))
		}

		fmt.Printf("Feature '%s' deleted successfully on '%s'\n", featureName, hostName)
		return nil
	},
}

// // hostServiceCommand handles 'deploy host <host name or id> service'
// var hostServiceCommand = &cli.Command{
// 	Keyword: "service",
// 	Aliases: []string{"svc"},

// 	Commands: []*cli.Command{
// 		hostServiceListCommand,
// 		hostServiceAddCommand,
// 		hostServiceAvailableCommand,
// 		hostServiceCheckCommand,
// 		hostServiceDeleteCommand,
// 		hostServiceStartCommand,
// 		hostServiceStateCommand,
// 		hostServiceStopCommand,
// 	},

// 	Before: func(c *cli.Command) {
// 		hostServiceName = c.StringArgument("<svcname>", "")
// 		if hostServiceName == "" {
// 			fmt.Println("Invalid argument <svcname>")
// 			os.Exit(int(ExitCode.InvalidArgument))
// 		}
// 	},

// 	Help: &cli.HelpContent{
// 		Usage: `
// Usage: {{.ProgName}} [options] host <host name or id> service,svc [<arg>...]`,
// 		Description: `
// Manages services on a single host.`,
// 	},
// }

// // hostServiceListCommand handles 'deploy host <host name or id> service list'
// var hostServiceListCommand = &cli.Command{
// 	Keyword: "list",
// 	Aliases: []string{"ls"},

// 	Process: func(c *cli.Command) {
// 		fmt.Println("hostServiceListCommand not yet implemented")
// 		os.Exit(int(ExitCode.NotImplemented))
// 	},

// 	Help: &cli.HelpContent{},
// }

// // hostServiceAvailableCommand handles 'deploy host <host name or id> service <svcname> available'
// var hostServiceAvailableCommand = &cli.Command{
// 	Keyword: "available",
// 	Aliases: []string{"avail", "installable"},

// 	Process: func(c *cli.Command) {
// 		fmt.Println("hostServiceAvailableCommand not yet implemented")
// 		os.Exit(int(ExitCode.NotImplemented))
// 	},

// 	Help: &cli.HelpContent{},
// }

// // hostServiceCheckCommand handles 'deploy host <host name or id> service <pkgname> check'
// var hostServiceCheckCommand = &cli.Command{
// 	Keyword: "check",

// 	Process: func(c *cli.Command) {
// 		fmt.Println("hostServiceCheckCommand not yet implemented")
// 		os.Exit(int(ExitCode.NotImplemented))
// 	},

// 	Help: &cli.HelpContent{},
// }

// // hostServiceAddCommand handles 'deploy host <host name or id> services <svcname> add'
// var hostServiceAddCommand = &cli.Command{
// 	Keyword: "add",
// 	Aliases: []string{"install"},

// 	Process: func(c *cli.Command) {
// 		fmt.Println("hostServiceAddCommand not yet implemented")
// 		os.Exit(int(ExitCode.NotImplemented))
// 	},

// 	Help: &cli.HelpContent{},
// }

// // hostServiceDeleteCommand handles 'deploy host <host name or id> service <svcname> delete'
// var hostServiceDeleteCommand = &cli.Command{
// 	Keyword: "delete",
// 	Aliases: []string{"destroy", "remove", "rm"},

// 	Process: func(c *cli.Command) {
// 		fmt.Println("hostServiceDeleteCommand not yet implemented")
// 		os.Exit(int(ExitCode.NotImplemented))
// 	},

// 	Help: &cli.HelpContent{},
// }

// // hostServiceStartCommand handles 'deploy host <host name or id> service <svcname> start'
// var hostServiceStartCommand = &cli.Command{
// 	Keyword: "start",

// 	Process: func(c *cli.Command) {
// 		fmt.Println("hostServiceStartCommand not yet implemented")
// 		os.Exit(int(ExitCode.NotImplemented))
// 	},

// 	Help: &cli.HelpContent{},
// }

// // hostServiceStateCommand handles 'deploy host <host name or id> service <svcname> state'
// var hostServiceStateCommand = &cli.Command{
// 	Keyword: "state",

// 	Process: func(c *cli.Command) {
// 		fmt.Println("hostServiceStateCommand not yet implemented")
// 		os.Exit(int(ExitCode.NotImplemented))
// 	},

// 	Help: &cli.HelpContent{},
// }

// // hostServiceStopCommand handles 'deploy host <host name or id> service <svcname> stop'
// var hostServiceStopCommand = &cli.Command{
// 	Keyword: "stop",

// 	Process: func(c *cli.Command) {
// 		fmt.Println("hostServiceStopCommand not yet implemented")
// 		os.Exit(int(ExitCode.NotImplemented))
// 	},

// 	Help: &cli.HelpContent{},
// }

// // hostDockerCommand handles 'deploy host <host name or id> docker'
// var hostDockerCommand = &cli.Command{
// 	Keyword: "docker",

// 	Process: func(c *cli.Command) {
// 		fmt.Println("hostDockerCommand not yet implemented")
// 		os.Exit(int(ExitCode.NotImplemented))
// 	},

// 	Help: &cli.HelpContent{},
// }
