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
	"os"
	"strings"

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"

	cli "github.com/CS-SI/SafeScale/utils/cli"
	"github.com/CS-SI/SafeScale/utils/cli/ExitCode"

	"github.com/CS-SI/SafeScale/deploy/install"
)

var (
	hostName     string
	hostInstance *pb.Host
	featureName  string
)

// HostCommand handles 'deploy host'
var HostCommand = &cli.Command{
	Keyword: "host",

	Commands: []*cli.Command{
		hostFeatureCommand,
		hostServiceCommand,
	},

	Before: func(c *cli.Command) {
		if !c.IsKeywordSet("list,ls") {
			hostName = c.StringArgument("<host name or id>", "")
			if hostName == "" {
				fmt.Fprintln(os.Stderr, "Invalid argument <host name or id>")
				os.Exit(int(ExitCode.InvalidArgument))
			}
			var err error
			hostInstance, err = brokerclient.New().Host.Inspect(hostName, 0)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to get definition of host '%s': %s\n", hostName, err.Error())
				os.Exit(int(ExitCode.RPC))
			}
		}
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} host list|ls
       {{.ProgName}} [options] host <host name or id> COMMAND
`,
		Commands: `
  feature  Manages SafeScale features
  service,svc  Manages operating system service`,
		Description: `
Deploy package and service on a single host.`,
		Footer: `
Run 'deploy host COMMAND --help' for more information on a command.`,
	},
}

// hostFeatureCommand handles 'deploy host <host name or id> feature'
var hostFeatureCommand = &cli.Command{
	Keyword: "feature",
	Aliases: []string{"package", "pkg"},

	Commands: []*cli.Command{
		hostFeatureCheckCommand,
		hostFeatureAddCommand,
		hostFeatureDeleteCommand,
	},

	Before: func(c *cli.Command) {
		featureName = c.StringArgument("<pkgname>", "")
		if featureName == "" {
			fmt.Fprintln(os.Stderr, "Invalid argument <pkgname>")
			//helpHandler(nil, "")
			os.Exit(int(ExitCode.InvalidArgument))
		}
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] host <host name or id> feature,package,pkg <pkgname> COMMAND`,
		Commands: `
  add,install                         Installs the package on the host
  check                               Tells if the package is installed
  delete,destroy,remove,rm,uninstall  Uninstall the package of the host`,
		Description: `
Manages features (SafeScale packages) on a single host.`,
	},
}

// hostFeatureAddCommand handles 'deploy host <host name or id> package <pkgname> add'
var hostFeatureAddCommand = &cli.Command{
	Keyword: "add",
	Aliases: []string{"install"},

	Process: func(c *cli.Command) {
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
		anon := c.Option("--param", "<param>")
		if anon != nil {
			params := anon.([]string)
			for _, k := range params {
				res := strings.Split(k, "=")
				if len(res[0]) > 0 {
					values[res[0]] = strings.Join(res[1:], "=")
				}
			}
		}

		settings := install.Settings{}
		settings.SkipProxy = c.Flag("--skip-proxy", false)

		// Wait for SSH service on remote host first
		err = brokerclient.New().Ssh.WaitReady(hostInstance.ID, brokerclient.DefaultConnectionTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to reach '%s': %s", hostName, brokerclient.DecorateError(err, "waiting ssh on host", false))
			os.Exit(int(ExitCode.RPC))
		}

		target := install.NewHostTarget(hostInstance)
		results, err := feature.Add(target, values, settings)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error installing feature '%s' on host '%s': %s\n", featureName, hostName, err.Error())
			os.Exit(int(ExitCode.RPC))
		}
		if results.Successful() {
			fmt.Printf("Feature '%s' installed successfully on host '%s'\n", featureName, hostName)
			os.Exit(int(ExitCode.OK))
		}

		fmt.Printf("Failed to install feature '%s' on host '%s'\n", featureName, hostName)
		fmt.Println(results.AllErrorMessages())
		os.Exit(int(ExitCode.Run))
	},

	Help: &cli.HelpContent{},
}

// hostFeatureCheckCommand handles 'deploy host <host name or id> package <pkgname> check'
var hostFeatureCheckCommand = &cli.Command{
	Keyword: "check",
	Aliases: []string{"verify"},

	Process: func(c *cli.Command) {
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
		anon := c.Option("--param", "<param>")
		if anon != nil {
			params := anon.([]string)
			for _, k := range params {
				res := strings.Split(k, "=")
				if len(res[0]) > 0 {
					values[res[0]] = strings.Join(res[1:], "=")
				}
			}
		}

		// Wait for SSH service on remote host first
		err = brokerclient.New().Ssh.WaitReady(hostInstance.ID, brokerclient.DefaultConnectionTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to reach '%s': %s", hostName, brokerclient.DecorateError(err, "waiting ssh on host", false))
			os.Exit(int(ExitCode.RPC))
		}

		target := install.NewHostTarget(hostInstance)
		results, err := feature.Check(target, values, install.Settings{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking if feature '%s' is installed on '%s': %s\n", featureName, hostName, err.Error())
			os.Exit(int(ExitCode.RPC))
		}
		if results.Successful() {
			fmt.Printf("Feature '%s' is installed on '%s'\n", featureName, hostName)
			os.Exit(int(ExitCode.OK))
		}
		fmt.Printf("Feature '%s' is not installed on '%s'\n", featureName, hostName)
		msg := results.AllErrorMessages()
		if msg != "" {
			fmt.Println(msg)
		}
		os.Exit(int(ExitCode.NotFound))
	},

	Help: &cli.HelpContent{},
}

// hostFeatureDeleteCommand handles 'deploy host <host name or id> package <pkgname> delete'
var hostFeatureDeleteCommand = &cli.Command{
	Keyword: "delete",
	Aliases: []string{"destroy", "remove", "rm", "uninstall"},

	Process: func(c *cli.Command) {
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
		anon := c.Option("--param", "<param>")
		if anon != nil {
			params := anon.([]string)
			for _, k := range params {
				res := strings.Split(k, "=")
				if len(res[0]) > 0 {
					values[res[0]] = strings.Join(res[1:], "=")
				}
			}
		}

		// Wait for SSH service on remote host first
		err = brokerclient.New().Ssh.WaitReady(hostInstance.ID, brokerclient.DefaultConnectionTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to reach '%s': %s", hostName, brokerclient.DecorateError(err, "waiting ssh on host", false))
			os.Exit(int(ExitCode.RPC))
		}

		target := install.NewHostTarget(hostInstance)
		results, err := feature.Remove(target, values, install.Settings{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error uninstalling feature '%s' on '%s': %s\n", featureName, hostName, err.Error())
			os.Exit(int(ExitCode.RPC))
		}
		if results.Successful() {
			fmt.Printf("Feature '%s' uninstalled successfully on '%s'\n", featureName, hostName)
			os.Exit(int(ExitCode.OK))
		}
		fmt.Printf("Failed to uninstall feature '%s' from host '%s':\n", featureName, hostName)
		msg := results.AllErrorMessages()
		if msg != "" {
			fmt.Println(msg)
		}
		os.Exit(int(ExitCode.Run))
	},

	Help: &cli.HelpContent{},
}

// hostServiceCommand handles 'deploy host <host name or id> service'
var hostServiceCommand = &cli.Command{
	Keyword: "service",
	Aliases: []string{"svc"},

	Commands: []*cli.Command{
		hostServiceListCommand,
		hostServiceAddCommand,
		hostServiceAvailableCommand,
		hostServiceCheckCommand,
		hostServiceDeleteCommand,
		hostServiceStartCommand,
		hostServiceStateCommand,
		hostServiceStopCommand,
	},

	Before: func(c *cli.Command) {
		svcName = c.StringArgument("<svcname>", "")
		if svcName == "" {
			fmt.Println("Invalid argument <svcname>")
			os.Exit(int(ExitCode.InvalidArgument))
		}
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] host <host name or id> service,svc [<arg>...]`,
		Description: `
Manages services on a single host.`,
	},
}

// hostServiceListCommand handles 'deploy host <host name or id> service list'
var hostServiceListCommand = &cli.Command{
	Keyword: "list",
	Aliases: []string{"ls"},

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceListCommand not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostServiceAvailableCommand handles 'deploy host <host name or id> service <svcname> available'
var hostServiceAvailableCommand = &cli.Command{
	Keyword: "available",
	Aliases: []string{"avail", "installable"},

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceAvailableCommand not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostServiceCheckCommand handles 'deploy host <host name or id> service <pkgname> check'
var hostServiceCheckCommand = &cli.Command{
	Keyword: "check",

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceCheckCommand not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostServiceAddCommand handles 'deploy host <host name or id> services <svcname> add'
var hostServiceAddCommand = &cli.Command{
	Keyword: "add",
	Aliases: []string{"install"},

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceAddCommand not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostServiceDeleteCommand handles 'deploy host <host name or id> service <svcname> delete'
var hostServiceDeleteCommand = &cli.Command{
	Keyword: "delete",
	Aliases: []string{"destroy", "remove", "rm"},

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceDeleteCommand not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostServiceStartCommand handles 'deploy host <host name or id> service <svcname> start'
var hostServiceStartCommand = &cli.Command{
	Keyword: "start",

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceStartCommand not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostServiceStateCommand handles 'deploy host <host name or id> service <svcname> state'
var hostServiceStateCommand = &cli.Command{
	Keyword: "state",

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceStateCommand not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostServiceStopCommand handles 'deploy host <host name or id> service <svcname> stop'
var hostServiceStopCommand = &cli.Command{
	Keyword: "stop",

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceStopCommand not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostDockerCommand handles 'deploy host <host name or id> docker'
var hostDockerCommand = &cli.Command{
	Keyword: "docker",

	Process: func(c *cli.Command) {
		fmt.Println("hostDockerCommand not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}
