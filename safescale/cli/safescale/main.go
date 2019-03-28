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

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"path"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/CS-SI/SafeScale/safescale/client"
	"github.com/CS-SI/SafeScale/safescale/utils"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/safescale/cli/safescale/cmd"
)

func cleanup() {
	fmt.Println("\nBe carfull stopping safescale will not stop the execution on safescaled, but will try to go back to the previous state as much as possible!")
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Do you really want to stop the command ? [y]es [n]o: ")
	text, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Failed to read the imput : ", err.Error())
		text = "y"
	}
	if strings.TrimRight(text, "\n") == "y" {
		err = client.New().ProcessManager.Stop(utils.GetUUID(), client.DefaultExecutionTimeout)
		if err != nil {
			fmt.Printf("Failed to stop the process %v\n", err)
		}
		os.Exit(0)
	}
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for {
			<-c
			cleanup()
		}
	}()

	app := cli.NewApp()
	app.Writer = os.Stderr
	app.Name = "safescale"
	app.Usage = "safescale COMMAND"
	app.Version = VERSION + ", build " + REV + " (" + BUILD_DATE + ")"
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
		if strings.Contains(path.Base(os.Args[0]), "-cover") {
			log.SetLevel(log.DebugLevel)
			utils.Verbose = true
		} else {
			log.SetLevel(log.WarnLevel)
		}

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

	app.Commands = append(app.Commands, cmd.ClusterCommand)
	sort.Sort(cli.CommandsByName(cmd.ClusterCommand.Subcommands))

	sort.Sort(cli.CommandsByName(app.Commands))

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println("Error Running App : " + err.Error())
	}
}
