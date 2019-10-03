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

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/cli/safescale/commands"
	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"

	// Autoload embedded provider drivers
	_ "github.com/CS-SI/SafeScale/lib/server"
)

func cleanup() {
	fmt.Println("\nBe careful stopping safescale will not stop the execution on safescaled, but will try to go back to the previous state as much as possible!")
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Do you really want to stop the command ? [y]es [n]o: ")
	text, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("failed to read the input : ", err.Error())
		text = "y"
	}
	if strings.TrimRight(text, "\n") == "y" {
		err = client.New().JobManager.Stop(utils.GetUUID(), temporal.GetExecutionTimeout())
		if err != nil {
			fmt.Printf("failed to stop the process %v\n", err)
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
			log.SetLevel(log.TraceLevel)
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

	app.Commands = append(app.Commands, commands.NetworkCmd)
	sort.Sort(cli.CommandsByName(commands.NetworkCmd.Subcommands))

	app.Commands = append(app.Commands, commands.TenantCmd)
	sort.Sort(cli.CommandsByName(commands.TenantCmd.Subcommands))

	app.Commands = append(app.Commands, commands.HostCmd)
	sort.Sort(cli.CommandsByName(commands.HostCmd.Subcommands))

	app.Commands = append(app.Commands, commands.VolumeCmd)
	sort.Sort(cli.CommandsByName(commands.VolumeCmd.Subcommands))

	app.Commands = append(app.Commands, commands.SSHCmd)
	sort.Sort(cli.CommandsByName(commands.SSHCmd.Subcommands))

	app.Commands = append(app.Commands, commands.BucketCmd)
	sort.Sort(cli.CommandsByName(commands.BucketCmd.Subcommands))

	//VPL: data disabled, not ready
	// app.Commands = append(app.Commands, commands.DataCmd)
	// sort.Sort(cli.CommandsByName(commands.DataCmd.Subcommands))

	app.Commands = append(app.Commands, commands.ShareCmd)
	sort.Sort(cli.CommandsByName(commands.ShareCmd.Subcommands))

	app.Commands = append(app.Commands, commands.ImageCmd)
	sort.Sort(cli.CommandsByName(commands.ImageCmd.Subcommands))

	app.Commands = append(app.Commands, commands.TemplateCmd)
	sort.Sort(cli.CommandsByName(commands.TemplateCmd.Subcommands))

	app.Commands = append(app.Commands, commands.ClusterCommand)
	sort.Sort(cli.CommandsByName(commands.ClusterCommand.Subcommands))

	sort.Sort(cli.CommandsByName(app.Commands))

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println("Error Running App : " + err.Error())
	}
}
