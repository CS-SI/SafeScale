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

package main

// TODO NOTICE Side-effects imports here
import (
	"log"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/cli/perform/commands"

	_ "github.com/CS-SI/SafeScale/lib/server"
)

func main() {

	cli.VersionFlag = cli.BoolFlag{
		Name:  "version, V",
		Usage: "print version",
	}

	app := cli.NewApp()
	app.Name = "perform"
	app.Usage = "perform COMMAND"
	app.Version = Version + ", build " + Revision + " (" + BuildDate + ")"
	app.Copyright = "(c) 2018-2019 CS-SI"
	app.Compiled = time.Now()
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "CS-SI",
			Email: "safescale@c-s.fr",
		},
	}
	app.EnableBashCompletion = true

	safescaledPort := 50051

	if portCandidate := os.Getenv("SAFESCALED_PORT"); portCandidate != "" {
		num, err := strconv.Atoi(portCandidate)
		if err == nil {
			safescaledPort = num
		}
	}

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name: "verbose, v",
		},
		cli.BoolFlag{
			Name: "debug, d",
		},
		cli.IntFlag{
			Name:  "port, p",
			Usage: "Bind to specified port `PORT`",
			Value: safescaledPort,
		},
	}

	app.Commands = []cli.Command{
		commands.ClusterListCommand,
		commands.ClusterCreateCommand,
		commands.ClusterInspectCommand,
		commands.ClusterDeleteCommand,
		commands.ClusterStartCommand,
		commands.ClusterStopCommand,
		commands.ClusterStateCommand,
		commands.ClusterExpandCommand,
		commands.ClusterShrinkCommand,
		commands.ClusterCallCommand,
		commands.ClusterInspectNodeCommand,
		commands.ClusterDeleteNodeCommand,
		commands.ClusterStartNodeCommand,
		commands.ClusterStopNodeCommand,
		commands.ClusterProbeNodeCommand,
		commands.ClusterAddFeatureCommand,
		commands.ClusterDeleteFeatureCommand,
		commands.ClusterProbeFeatureCommand,
	}
	sort.Sort(cli.CommandsByName(app.Commands))

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
