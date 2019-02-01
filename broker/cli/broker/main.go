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
	"bufio"
	"fmt"
	"os"
	"runtime"
	"os/signal"
	"sort"
	"syscall"

	"github.com/dlespiau/covertool/pkg/exit"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/broker/cli/broker/cmd"
	"github.com/CS-SI/SafeScale/broker/utils"
)

func cleanup() {
	fmt.Println("\nBe carfull stoping broker will not stop the execution on brokerd!")
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for {
			<-c
			cleanup()
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Do you really want to stop broker ? [y]es [n]o: ")
			text, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println("Failed to read the imput : ", err.Error())
				text = "y"
			}
			if text == "y" {
				exit.Exit(1)
			}
		}
	}()

	app := cli.NewApp()
	app.Name = "broker"
	app.Usage = "broker COMMAND"
	app.Version = VERSION + "-" + BUILD_DATE + "-" + REV
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "CS-SI",
			Email: "safescale@c-s.fr",
		},
	}

	app.EnableBashCompletion = true

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
			Usage: "Show debug information",
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
			utils.Verbose = true
		}
		if c.GlobalBool("debug") {
			log.SetLevel(log.DebugLevel)
			utils.Debug = true
		}
		return nil
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

	app.Commands = append(app.Commands, cmd.BucketCmd)
	sort.Sort(cli.CommandsByName(cmd.BucketCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.ShareCmd)
	sort.Sort(cli.CommandsByName(cmd.ShareCmd.Subcommands))

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
