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

	"github.com/CS-SI/SafeScale/deploy/cli/cmds"

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
  -d,--debug    Enable debug supplemental information
`

	completeUsage string = `
Usage: deploy version
       deploy [-vd] help (cluster|host)
       deploy [-vd] (cluster|datacenter|dc|host) help <command>
       deploy [-vd] (cluster|datacenter|dc|host) (list|ls)
       deploy [-vd] (cluster|datacenter|dc) help <command>
       deploy [-vd] (cluster|datacenter|dc) <clustername> create [-N <cidr>][-F <flavor>][-C <complexity][--os <operating system>][--cpu <number of cpu>][--ram <ram size>][--disk <disk size>][-k][(--disable-feature <feature>)...]
       deploy [-vd] (cluster|datacenter|dc) <clustername> (delete|destroy|remove|rm) [-y]
       deploy [-vd] (cluster|datacenter|dc) <clustername> (start|stop|state|inspect)
       deploy [-vd] (cluster|datacenter|dc) <clustername> expand [-n <count>][--os <os>][--cpu <number of cpu>][--ram <ram size>][--disk <disk size>]
       deploy [-vd] (cluster|datacenter|dc) <clustername> shrink [-n <count>]
       deploy [-vd] (cluster|datacenter|dc) <clustername> feature <pkgname> (add|install) [-f][--skip-proxy][--no-master][--no-node][(--param <param>)...]
       deploy [-vd] (cluster|datacenter|dc) <clustername> feature <pkgname> check [(--param <param>)...]
       deploy [-vd] (cluster|datacenter|dc) <clustername> feature <pkgname> (delete|destroy|remove|rm|uninstall) [-f][(--param <param>)...]
       deploy [-vd] (cluster|datacenter|dc) <clustername> (service|svc) <pkgname> (check|start|state|stop|pause|resume)
       deploy [-vd] (cluster|datacenter|dc) <clustername> (dcos|marathon|kubectl) [-- <arg>...]
       deploy [-vd] (cluster|datacenter|dc) <clustername> nas <nasname> create [-u <storage unit size>][-n <count>][--host <nas host>]
       deploy [-vd] (cluster|datacenter|dc) <clustername> nas <nasname> (expand|shrink) [-n <count>]
       deploy [-vd] (cluster|datacenter|dc) <clustername> nas <nasname> (delete|destroy|remove|rm) [-y]
       deploy [-vd] (cluster|datacenter|dc) <clustername> nas <nasname> share <sharename> create [(--acl <acl>)...]
       deploy [-vd] (cluster|datacenter|dc) <clustername> nas <nasname> share <sharename> (delete|destroy|remove|rm)
       deploy [-vd] (cluster|datacenter|dc) <clustername> nas <nasname> share <sharename> mount <mountpoint>
       deploy [-vd] (cluster|datacenter|dc) <clustername> nas <nasname> share <sharename> (umount|unmount)
       deploy [-vd] host help <command>
       deploy [-vd] host <host_name_or_id> feature <pkgname> (add|install) [(--param <param>)...]
       deploy [-vd] host <host_name_or_id> feature <pkgname> check
       deploy [-vd] host <host_name_or_id> feature <pkgname> (delete|destroy|remove|rm|uninstall)
       deploy [-vd] host <host_name_or_id> (service|svc) <pkgname> (check|start|state|stop|pause|resume)

Options:
  -C <complexity>,--complexity <complexity>               Defines complexity
  -d,--debug                                              Enable debug suplemental information
  -F <flavor>,--flavor <flavor>                           Defines flavor
  -f,--force                                              Force action even when an error occured
  -h,--help                                               Print help message
  -k,--keep-on-failure                                    Don't delete the resources on failure
  -N <cidr>,--cidr <cidr>                                 Defines CIDR
  -n <count>,--count <count>                              Defines the number
  -u <storage unit size>,--unit-size <storage unit size>  Defines the size in GB of a storage unit size for the nas
  -v,--verbose                                            Enable verbosity
  -y,--assume-yes                                         Automatically responds y to confirmation
  -p,--param <param>                                      Used to set parameter of feature
  --host <nas host>                                       By default, nas create creates a new host; with this option, add nas functionality on existing host
  --cpu <cpu>                                             Defines number of CPU of host
  --disk <disk>                                           Defines system disk size
  --os <os>                                               Defines Linux Operating System
  --ram <ram>                                             Defines ram size
  --skip-proxy                                            Disables reverse proxy configuration
  --no-check                                              Disables feature check before add or remove
  --no-master                                             Disables feature installation on master(s)
  --no-node                                               Disables feature installation on node(s)
  --disable-feature <feature>                             Disables a default feature (remotedesktop)`
)

func main() {
	app := cli.NewApp(completeUsage, &cli.Command{
		Keyword: "deploy",

		Commands: []*cli.Command{
			cmds.ClusterCommand,
			cmds.HostCommand,
		},

		Before: func(c *cli.Command) {
			cmds.Verbose = c.Flag("-v,--verbose", false)
			cmds.Debug = c.Flag("-d,--debug", false)
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
