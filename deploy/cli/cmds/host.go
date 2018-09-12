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
	installapi "github.com/CS-SI/SafeScale/deploy/install/api"
)

var (
	hostName      string
	hostInstance  *pb.Host
	componentName string
)

// HostCommand handles 'deploy host'
var HostCommand = &cli.Command{
	Keyword: "host",

	Commands: []*cli.Command{
		hostComponentCommand,
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
  component  Manages SafeScale components
  service,svc  Manages operating system service`,
		Description: `
Deploy package and service on a single host.`,
		Footer: `
Run 'deploy host COMMAND --help' for more information on a command.`,
	},
}

// hostComponentCommand handles 'deploy host <host name or id> component'
var hostComponentCommand = &cli.Command{
	Keyword: "component",
	Aliases: []string{"package", "pkg"},

	Commands: []*cli.Command{
		hostComponentCheckCommand,
		hostComponentAddCommand,
		hostComponentDeleteCommand,
	},

	Before: func(c *cli.Command) {
		componentName = c.StringArgument("<pkgname>", "")
		if componentName == "" {
			fmt.Fprintln(os.Stderr, "Invalid argument <pkgname>")
			//helpHandler(nil, "")
			os.Exit(int(ExitCode.InvalidArgument))
		}
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] host <host name or id> component,package,pkg <pkgname> COMMAND`,
		Commands: `
  add,install                         Installs the package on the host
  check                               Tells if the package is installed
  delete,destroy,remove,rm,uninstall  Uninstall the package of the host`,
		Description: `
Manages components (SafeScale packages) on a single host.`,
	},
}

// hostComponentAddCommand handles 'deploy host <host name or id> package <pkgname> add'
var hostComponentAddCommand = &cli.Command{
	Keyword: "add",
	Aliases: []string{"install"},

	Process: func(c *cli.Command) {
		component, err := install.NewComponent(componentName)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(int(ExitCode.Run))
		}
		if component == nil {
			fmt.Fprintf(os.Stderr, "Failed to find a component named '%s'.\n", componentName)
			os.Exit(int(ExitCode.NotFound))
		}
		values := installapi.Variables{}
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
		ok, results, err := component.Add(target, values)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error installing component '%s' on host '%s': %s\n", componentName, hostName, err.Error())
			os.Exit(int(ExitCode.RPC))
		}
		if ok {
			fmt.Printf("Component '%s' installed successfully on host '%s'\n", componentName, hostName)
			os.Exit(int(ExitCode.OK))
		}

		fmt.Printf("Failed to install component '%s' on host '%s'\n", componentName, hostName)
		fmt.Println(results.Errors())
		os.Exit(int(ExitCode.Run))
	},

	Help: &cli.HelpContent{},
}

// hostComponentCheckCommand handles 'deploy host <host name or id> package <pkgname> check'
var hostComponentCheckCommand = &cli.Command{
	Keyword: "check",
	Aliases: []string{"verify"},

	Process: func(c *cli.Command) {
		component, err := install.NewComponent(componentName)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(int(ExitCode.Run))
		}
		if component == nil {
			fmt.Fprintf(os.Stderr, "Failed to find a component named '%s'.\n", componentName)
			os.Exit(int(ExitCode.NotFound))
		}

		// Wait for SSH service on remote host first
		err = brokerclient.New().Ssh.WaitReady(hostInstance.ID, brokerclient.DefaultConnectionTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to reach '%s': %s", hostName, brokerclient.DecorateError(err, "waiting ssh on host", false))
			os.Exit(int(ExitCode.RPC))
		}

		target := install.NewHostTarget(hostInstance)
		found, results, err := component.Check(target, installapi.Variables{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking if component '%s' is installed on '%s': %s\n", componentName, hostName, err.Error())
			os.Exit(int(ExitCode.RPC))
		}
		if found {
			fmt.Printf("Component '%s' is installed on '%s'\n", componentName, hostName)
			os.Exit(int(ExitCode.OK))
		}
		fmt.Printf("Component '%s' is not installed on '%s'\n", componentName, hostName)
		msg := results.Errors()
		if msg != "" {
			fmt.Println(msg)
		}
		os.Exit(int(ExitCode.NotFound))
	},

	Help: &cli.HelpContent{},
}

// hostComponentDeleteCommand handles 'deploy host <host name or id> package <pkgname> delete'
var hostComponentDeleteCommand = &cli.Command{
	Keyword: "delete",
	Aliases: []string{"destroy", "remove", "rm", "uninstall"},

	Process: func(c *cli.Command) {
		component, err := install.NewComponent(componentName)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(int(ExitCode.Run))
		}
		if component == nil {
			fmt.Fprintf(os.Stderr, "Failed to find a component named '%s'.\n", componentName)
			os.Exit(int(ExitCode.NotFound))
		}

		// Wait for SSH service on remote host first
		err = brokerclient.New().Ssh.WaitReady(hostInstance.ID, brokerclient.DefaultConnectionTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to reach '%s': %s", hostName, brokerclient.DecorateError(err, "waiting ssh on host", false))
			os.Exit(int(ExitCode.RPC))
		}

		target := install.NewHostTarget(hostInstance)
		ok, results, err := component.Remove(target, installapi.Variables{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error uninstalling component '%s' on '%s': %s\n", componentName, hostName, err.Error())
			os.Exit(int(ExitCode.RPC))
		}
		if ok {
			fmt.Printf("Component '%s' uninstalled successfully on '%s'\n", componentName, hostName)
			os.Exit(int(ExitCode.OK))
		}
		fmt.Printf("Failed to uninstall component '%s' from host '%s':\n", componentName, hostName)
		msg := results.Errors()
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
