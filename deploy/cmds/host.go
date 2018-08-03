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

	"github.com/CS-SI/SafeScale/deploy/cmds/ErrorCode"
	cli "github.com/CS-SI/SafeScale/utils/cli"
)

var (
	hostName string
)

// HostCommand handles 'deploy host'
var HostCommand = &cli.Command{
	Keyword: "host",

	Commands: []*cli.Command{
		hostListCommand,
		hostInspectCommand,
		hostPackageCommand,
		hostServiceCommand,
	},

	Before: func(c *cli.Command) {
		if !c.IsCommandSet("list,ls") {
			hostName = c.StringArgument("<host name or id>", "")
			if hostName == "" {
				fmt.Println("Invalid argument <host name or id>")
				os.Exit(int(ErrorCode.InvalidArgument))
			}
		}
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.Progname}} host list|ls
       {{.ProgName}} [options] host <host name or id> COMMAND
`,
		Commands: `
Commands:
  inspect      Display detailed information about the host
  package,pkg  Manages operating system package
  service,svc  Manages operating system service`,
		Description: `
Deploy package and service on a single host.`,
		Footer: `
Run 'deploy host COMMAND --help' for more information on a command.`,
	},
}

// hostListCommand handles 'deploy host list' (duplicate with broker, not sure we keep that...)
var hostListCommand = &cli.Command{
	Keyword: "list",
	Aliases: []string{"ls"},

	Process: func(c *cli.Command) {
		fmt.Println("hostListCommand not yet implemented")
		os.Exit(int(ErrorCode.NotImplemented))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] host list,ls`,
		Description: `
List available hosts.`,
	},
}

// hostInspectCommand handles 'deploy host <host name or id> inspect' (duplicate with broker, not sure we keep that)
var hostInspectCommand = &cli.Command{
	Keyword: "inspect",

	Process: func(c *cli.Command) {
		fmt.Println("hostInspectCommand not yet implemented")
		os.Exit(int(ErrorCode.NotImplemented))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: deploy [options] host <host name or id> inspect`,
		Description: `
Displays information about the host 'hostname'.`,
	},
}

// hostPackageCommand handles 'deploy host <host name or id> package'
var hostPackageCommand = &cli.Command{
	Keyword: "package",
	Aliases: []string{"pkg"},

	Commands: []*cli.Command{
		hostPackageAddCommand,
		hostPackageCheckCommand,
		hostPackageDeleteCommand,
	},

	Before: func(c *cli.Command) {
		pkgName = c.StringArgument("<pkgname>", "")
		if hostName == "" {
			fmt.Println("Invalid argument <pkgname>")
			//helpHandler(nil, "")
			os.Exit(int(ErrorCode.InvalidArgument))
		}
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] host <host name or id> package,pkg <pkgname> COMMAND`,
		Commands: `
  add,install                         Installs the package on the host
  check                               Tells if the package is installed
  delete,destroy,remove,rm,uninstall  Uninstall the package of the host`,
		Description: `
Manages operating system on a single host.`,
	},
}

// hostPackageAddCommand handles 'deploy host <host name or id> package <pkgname> add'
var hostPackageAddCommand = &cli.Command{
	Keyword: "add",
	Aliases: []string{"install"},

	Process: func(c *cli.Command) {
		fmt.Println("hostPackageAddCommand not yet implemented")
		os.Exit(int(ErrorCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostPackageCheckCommand handles 'deploy host <host name or id> package <pkgname> check'
var hostPackageCheckCommand = &cli.Command{
	Keyword: "check",
	Aliases: []string{"verify"},

	Process: func(c *cli.Command) {
		fmt.Println("hostPackageCheckCommand not yet implemented")
		os.Exit(int(ErrorCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostPackageDeleteCommand handles 'deploy host <host name or id> package <pkgname> delete'
var hostPackageDeleteCommand = &cli.Command{
	Keyword: "delete",
	Aliases: []string{"destroy", "remove", "rm", "uninstall"},

	Process: func(c *cli.Command) {
		fmt.Println("hostPackageDeleteCommand not yet implemented")
		os.Exit(int(ErrorCode.NotImplemented))
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
			os.Exit(int(ErrorCode.InvalidArgument))
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
		os.Exit(int(ErrorCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostServiceAvailableCommand handles 'deploy host <host name or id> service <svcname> available'
var hostServiceAvailableCommand = &cli.Command{
	Keyword: "available",
	Aliases: []string{"avail", "installable"},

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceAvailableCommand not yet implemented")
		os.Exit(int(ErrorCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostServiceCheckCommand handles 'deploy host <host name or id> service <pkgname> check'
var hostServiceCheckCommand = &cli.Command{
	Keyword: "check",

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceCheckCommand not yet implemented")
		os.Exit(int(ErrorCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostServiceAddCommand handles 'deploy host <host name or id> services <svcname> add'
var hostServiceAddCommand = &cli.Command{
	Keyword: "add",
	Aliases: []string{"install"},

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceAddCommand not yet implemented")
		os.Exit(int(ErrorCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostServiceDeleteCommand handles 'deploy host <host name or id> service <svcname> delete'
var hostServiceDeleteCommand = &cli.Command{
	Keyword: "delete",
	Aliases: []string{"destroy", "remove", "rm"},

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceDeleteCommand not yet implemented")
		os.Exit(int(ErrorCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostServiceStartCommand handles 'deploy host <host name or id> service <svcname> start'
var hostServiceStartCommand = &cli.Command{
	Keyword: "start",

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceStartCommand not yet implemented")
		os.Exit(int(ErrorCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostServiceStateCommand handles 'deploy host <host name or id> service <svcname> state'
var hostServiceStateCommand = &cli.Command{
	Keyword: "state",

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceStateCommand not yet implemented")
		os.Exit(int(ErrorCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostServiceStopCommand handles 'deploy host <host name or id> service <svcname> stop'
var hostServiceStopCommand = &cli.Command{
	Keyword: "stop",

	Process: func(c *cli.Command) {
		fmt.Println("hostServiceStopCommand not yet implemented")
		os.Exit(int(ErrorCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// hostDockerCommand handles 'deploy host <host name or id> docker'
var hostDockerCommand = &cli.Command{
	Keyword: "docker",

	Process: func(c *cli.Command) {
		fmt.Println("hostDockerCommand not yet implemented")
		os.Exit(int(ErrorCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}
