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
	"os"
	"fmt"
	"sort"

	log "github.com/sirupsen/logrus"

	cli "github.com/urfave/cli"

	context "golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/CS-SI/SafeScale/broker/cli/broker/cmd"
)

func main() {

	app := cli.NewApp()
	app.Name = "broker"
	app.Usage = "broker COMMAND"
	app.Version = VERSION + "-" + BUILD_DATE
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

	app.Commands = append(app.Commands, cmd.NetworkCmd)
	sort.Sort(cli.CommandsByName(cmd.NetworkCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.TenantCmd)
	sort.Sort(cli.CommandsByName(cmd.TenantCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.HostCmd)
	sort.Sort(cli.CommandsByName(cmd.HostCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.VolumeCmd)
	sort.Sort(cli.CommandsByName(cmd.VolumeCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.SSHCmd)
	sort.Sort(cli.CommandsByName(cmd.SSHCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.ContainerCmd)
	sort.Sort(cli.CommandsByName(cmd.ContainerCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.NasCmd)
	sort.Sort(cli.CommandsByName(cmd.NasCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.ImageCmd)
	sort.Sort(cli.CommandsByName(cmd.ImageCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.TemplateCmd)
	sort.Sort(cli.CommandsByName(cmd.TemplateCmd.Subcommands))

	sort.Sort(cli.CommandsByName(app.Commands))
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}
