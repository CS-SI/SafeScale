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

// TODO NOTICE Side-effects imports here
import (
	"os"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/deploy/cli/cmds"
	_ "github.com/CS-SI/SafeScale/providers/cloudferro"     // Imported to initialise provider cloudferro
	_ "github.com/CS-SI/SafeScale/providers/cloudwatt"      // Imported to initialise provider cloudwatt
	_ "github.com/CS-SI/SafeScale/providers/flexibleengine" // Imported to initialise provider flexibleengine
	_ "github.com/CS-SI/SafeScale/providers/local"          // Imported to initialise provider local
	_ "github.com/CS-SI/SafeScale/providers/opentelekom"    // Imported to initialise provider opentelekom
	_ "github.com/CS-SI/SafeScale/providers/ovh"            // Imported to initialise provider ovh
)

func main() {

	app := cli.NewApp()
	app.Name = "deploy"
	app.Usage = "deploy COMMAND"
	app.Version = VERSION + ", build date: " + BUILD_DATE + ", build hash: " + REV
	app.Copyright = "(c) 2018 CS-SI"
	app.Compiled = time.Now()
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "CS-SI",
			Email: "safescale@c-s.fr",
		},
	}

	cli.VersionFlag = cli.BoolFlag{
		Name:  "version, V",
		Usage: "Print program version",
	}

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, v",
			Usage: "Increase verbosity",
		},
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "Displays debug log",
		},
		// cli.IntFlag{
		// 	Name:  "port, p",
		// 	Usage: "Bind to specified port `PORT`",
		// 	Value: 50051,
		// },
	}

	app.Before = func(c *cli.Context) error {
		log.SetLevel(log.WarnLevel)
		if c.GlobalBool("verbose") {
			log.SetLevel(log.InfoLevel)
			cmds.Verbose = true
		}
		if c.GlobalBool("debug") {
			log.SetLevel(log.DebugLevel)
			cmds.Debug = true
		}
		return nil
	}

	app.EnableBashCompletion = true

	app.Commands = append(app.Commands, cmds.ClusterCommand)
	sort.Sort(cli.CommandsByName(cmds.ClusterCommand.Subcommands))

	app.Commands = append(app.Commands, cmds.HostCommand)
	sort.Sort(cli.CommandsByName(cmds.HostCommand.Subcommands))

	sort.Sort(cli.CommandsByName(app.Commands))
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
