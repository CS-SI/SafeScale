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
	"log"
	"os"
	"sort"
	"time"

	"github.com/CS-SI/SafeScale/deploy/cli/cmds"

	"github.com/urfave/cli"

	_ "github.com/CS-SI/SafeScale/providers/cloudwatt"      // Imported to initialise provider cloudwatt
	_ "github.com/CS-SI/SafeScale/providers/flexibleengine" // Imported to initialise provider flexibleengine
	_ "github.com/CS-SI/SafeScale/providers/opentelekom"    // Imported to initialise provider opentelekom
	_ "github.com/CS-SI/SafeScale/providers/ovh"            // Imported to initialise provider ovh
)

func main() {

	cli.VersionFlag = cli.BoolFlag{
		Name:  "version, V",
		Usage: "print version",
	}

	app := cli.NewApp()
	app.Name = "deploy"
	app.Usage = "deploy COMMAND"
	app.Version = "0.0.1"
	app.Copyright = "(c) 2018 CS-SI"
	app.Compiled = time.Now()
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "CS-SI",
			Email: "safescale@c-s.fr",
		},
	}
	app.EnableBashCompletion = true

	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "port, p",
			Usage: "Bind to specified port `PORT`",
			Value: 50051,
		},
	}

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
