/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"sync/atomic"
	"syscall"

	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/commands"
	"github.com/CS-SI/SafeScale/v22/lib/client"
	"github.com/CS-SI/SafeScale/v22/lib/server/utils"
	appwide "github.com/CS-SI/SafeScale/v22/lib/utils/app"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"

	// Autoload embedded provider drivers
	_ "github.com/CS-SI/SafeScale/v22/lib/server"
)

var profileCloseFunc = func() {}

func cleanup(clientSession *client.Session, onAbort *uint32) {
	var crash error
	defer fail.OnPanic(&crash) // nolint

	if atomic.CompareAndSwapUint32(onAbort, 0, 0) {
		profileCloseFunc()
		os.Exit(0) // nolint
	}

	fmt.Println("\nBe careful: stopping safescale will not stop the job on safescaled, but will try to go back to the previous state as much as possible.")
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Do you really want to stop the command ? [y]es [n]o: ")
	text, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("failed to read the input : ", err.Error())
		text = "y"
	}
	if strings.TrimRight(text, "\n") == "y" {
		err = clientSession.JobManager.Stop(utils.GetUUID(), temporal.ExecutionTimeout())
		if err != nil {
			fmt.Printf("failed to stop the process %v\n", err)
		}
	}
	profileCloseFunc()
	os.Exit(0)
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	var onAbort uint32

	// mainCtx, cancelfunc := context.WithCancel(context.Background())

	signalCh := make(chan os.Signal, 1)

	app := cli.NewApp()
	app.Writer = os.Stderr
	app.Name = "safescale"
	app.Usage = "safescale COMMAND"
	app.Version = Version + ", build " + Revision + " compiled with " + runtime.Version() + " (" + BuildDate + ")"
	if              //goland:noinspection GoBoolExpressions
	len(Tags) > 1 { // nolint
		app.Version += fmt.Sprintf(", with Tags: (%s)", Tags)
	}
	app.Authors = []cli.Author{
		{
			Name:  "CS-SI",
			Email: "safescale@csgroup.eu",
		},
	}

	app.EnableBashCompletion = true

	cli.VersionFlag = &cli.BoolFlag{
		Name:  "version, V",
		Usage: "Print program version",
	}

	app.Flags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "verbose, v",
			Usage: "Increase verbosity",
		},
		&cli.BoolFlag{
			Name:  "debug, d",
			Usage: "Show debug information",
		},
		&cli.StringFlag{
			Name: "profile",
			Usage: `Profiles binary
            value is a comma-separated list of <keyword> (ie '<keyword>[:<params>][,<keyword>[:<params>]...]) where <keyword>
            can be 'cpu', 'ram', 'trace', and 'web'.
            <params> may contain :
                for 'ram', 'cpu' and 'trace': optional destination folder of output file (default: current working directory)
                for 'web': [<listen addr>][:<listen port>] (default: 'localhost:6060')`,
		},
		&cli.StringFlag{
			Name:  "server, S",
			Usage: "Connect to daemon on server SERVER (default: localhost:50051)",
			Value: "",
		},
		&cli.StringFlag{
			Name:  "tenant, T",
			Usage: "Use tenant TENANT (default: none)",
		},
	}

	app.Before = func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		// Define trace settings of the application (what to trace if trace is wanted)
		// TODO: is it the good behavior ? Shouldn't we fail ?
		// If trace settings cannot be registered, report it but do not fail
		// TODO: introduce use of configuration file with autoreload on change
		err := tracing.RegisterTraceSettings(appTrace())
		if err != nil {
			logrus.Errorf(err.Error())
		}

		// Sets profiling
		if c.IsSet("profile") {
			what := c.String("profile")
			profileCloseFunc = debug.Profile(what)
		}

		// Default level is INFO
		logrus.SetLevel(logrus.InfoLevel)

		// Defines trace level wanted by user
		if appwide.Verbose = c.Bool("verbose"); appwide.Verbose {
			logrus.SetLevel(logrus.DebugLevel)
		}

		if appwide.Debug = c.Bool("debug"); appwide.Debug {
			logrus.SetLevel(logrus.DebugLevel)
		}

		if appwide.Debug && appwide.Verbose {
			logrus.SetLevel(logrus.TraceLevel)
		}

		if strings.Contains(path.Base(os.Args[0]), "-cover") {
			logrus.SetLevel(logrus.TraceLevel)
			appwide.Verbose = true
			appwide.Debug = true
		}

		commands.ClientSession, err = client.New(c.String("server"))
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}

		// Starts ctrl+c handler before app.RunContext()
		signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			var crash error
			defer fail.OnPanic(&crash)

			for {
				<-signalCh
				atomic.StoreUint32(&onAbort, 1)
				cleanup(commands.ClientSession, &onAbort)
				// cancelfunc()
			}
		}()
		return nil
	}

	app.After = func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		cleanup(commands.ClientSession, &onAbort)
		return nil
	}

	app.Commands = append(app.Commands, commands.NetworkCommand)
	sort.Sort(cli.CommandsByName(commands.NetworkCommand.Subcommands))

	app.Commands = append(app.Commands, commands.TenantCommand)
	sort.Sort(cli.CommandsByName(commands.TenantCommand.Subcommands))

	app.Commands = append(app.Commands, commands.HostCommand)
	sort.Sort(cli.CommandsByName(commands.HostCommand.Subcommands))

	app.Commands = append(app.Commands, commands.VolumeCommand)
	sort.Sort(cli.CommandsByName(commands.VolumeCommand.Subcommands))

	app.Commands = append(app.Commands, commands.SSHCommand)
	sort.Sort(cli.CommandsByName(commands.SSHCommand.Subcommands))

	app.Commands = append(app.Commands, commands.BucketCommand)
	sort.Sort(cli.CommandsByName(commands.BucketCommand.Subcommands))

	app.Commands = append(app.Commands, commands.ShareCommand)
	sort.Sort(cli.CommandsByName(commands.ShareCommand.Subcommands))

	app.Commands = append(app.Commands, commands.ImageCommand)
	sort.Sort(cli.CommandsByName(commands.ImageCommand.Subcommands))

	app.Commands = append(app.Commands, commands.TemplateCommand)
	sort.Sort(cli.CommandsByName(commands.TemplateCommand.Subcommands))

	app.Commands = append(app.Commands, commands.ClusterCommand)
	sort.Sort(cli.CommandsByName(commands.ClusterCommand.Subcommands))

	sort.Sort(cli.CommandsByName(app.Commands))

	// if last argument has "--" or "-" and is NOT help we are probably writing a wrong command
	/*
		{
			if len(os.Args) > 1 {
				last := os.Args[len(os.Args)-1]
				if !(last == "-help" || last == "--help" || last == "-h" || last == "--h") {
					if strings.HasPrefix(last, "-") {
						fmt.Printf("this might be a mistake, flags MUST be used BEFORE arguments: 'safescale subcommand arg1 arg2 --flag1 this_value_is_ignored', you should write 'safescale subcommand --flag1 this_value_now_works arg1 arg2'\n")
					}
				}
			}
		}
	*/

	// VPL: there is no RunContext in urfave/cli/v1
	// err := app.RunContext(mainCtx, os.Args)
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println("Error Running App : " + err.Error())
	}
}
