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

package main

import (
	"time"

	"github.com/CS-SI/SafeScale/deploy/cmds"

	"github.com/CS-SI/SafeScale/utils/cli"

	_ "github.com/CS-SI/SafeScale/providers/cloudwatt"      // Imported to initialise provider cloudwatt
	_ "github.com/CS-SI/SafeScale/providers/flexibleengine" // Imported to initialise provider flexibleengine
	_ "github.com/CS-SI/SafeScale/providers/opentelekom"    // Imported to initialise provider opentelekom
	_ "github.com/CS-SI/SafeScale/providers/ovh"            // Imported to initialise provider ovh
)

const (
	address           = "localhost:50051"
	timeoutCtxDefault = 10 * time.Second
	timeoutCtxHost    = 2 * time.Minute

	globalOptions string = `
Global options:
  -v,--verbose  Enable verbosity
  -d,--debug    Enable debug suplemental information
`

	completeUsage string = `
Usage: deploy version
       deploy [-vd] help (cluster|host)
       deploy [-vd] (cluster|host) help <command>
       deploy [-vd] (cluster|host) (list|ls)
	   deploy [-vd] cluster <clustername> create -N <cidr> [-F <flavor>][-C <complexity][--os <os>][--ram <ram>][--disk <disk>][-k]
	   deploy [-vd] cluster <clustername> (delete|destroy|remove|rm) [-y]
       deploy [-vd] cluster help <command>
       deploy [-vd] cluster <clustername> (start|stop|state|inspect)
       deploy [-vd] cluster <clustername> expand [-n <count>][--os <os>][--ram <ram>][--disk <disk>]
       deploy [-vd] cluster <clustername> shrink [-n <count>]
	   deploy [-vd] cluster <clustername> -K <kind> (package|pkg) <pkgname> (add|install)
	   deploy [-vd] cluster <clustername> -K <kind> (package|pkg) <pkgname> check
	   deploy [-vd] cluster <clustername> -K <kind> (package|pkg) <pkgname> (delete|destroy|remove|rm|uninstall)
	   deploy [-vd] cluster <clustername> (service|svc) <svcname> (add|install)
	   deploy [-vd] cluster <clustername> (service|svc) <pkgname> (check|start|state|stop)
	   deploy [-vd] cluster <clustername> (service|svc) <pkgname> (delete|destroy|remove|rm|uninstall)
	   deploy [-vd] cluster <clustername> (dcos|marathon|kubectl) [-- <arg>...]
	   deploy [-vd] host help <command>
	   deploy [-vd] host (package | pkg) help <command>
	   deploy [-vd] host <host name or id> (package|pkg) <pkgname> (add|install)
	   deploy [-vd] host <host name or id> (package|pkg) <pkgname> check
	   deploy [-vd] host <host name or id> (package|pkg) <pkgname> (delete|destroy|remove|rm|uninstall)
	   deploy [-vd] host <host name or id> (service|svc) <svcname> (add|install)
	   deploy [-vd] host <host name or id> (service|svc) <svcname> (check|start|state|stop)
	   deploy [-vd] host <host name or id> (service|svc) <svcname> (delete|destroy|remove|rm|uninstall)

Options:
  -C --complexity <complexity>  Defines complexity
  -d --debug                    Enable debug suplemental information
  -F --flavor <flavor>          Defines flavor
  -f --force                    Force action even when an error occured
  -h --help                     Print help message
  -K --kind <kind>              Defines kind of package manager
  -k --keep-on-failure          Don't delete the resources on failure
  -N --cidr <cidr>              Defines CIDR
  -v --verbose                  Enable verbosity
  -y --assume-yes               Automatically responds y to question
  --cpu <cpu>                   Defines number of CPU of host
  --disk <disk>                 Defines system disk size
  --os <os>                     Defines Linux Operating System
  --ram <ram>                   Defines ram size`
)

func main() {
	app := cli.NewApp(completeUsage, &cli.Command{
		Keyword: "deploy",

		Commands: []*cli.Command{
			cmds.ClusterCommand,
			cmds.HostCommand,
		},

		Help: &cli.HelpContent{
			Usage: `
Usage: {{.ProgName}} [options] <command>
       {{.ProgName}} [options] <command>
            `,
			Commands: `
  host     Deploy on host
  cluster  Deploy on cluster`,
			Options: []string{
				globalOptions,
			},
		},
	})
	app.Run(nil)
}
