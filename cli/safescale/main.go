/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
    "context"
    "fmt"
    "os"
    "os/signal"
    "path"
    "runtime"
    "sort"
    "strings"
    "syscall"

    "github.com/sirupsen/logrus"
    "github.com/urfave/cli/v2"

    "github.com/CS-SI/SafeScale/cli/safescale/commands"
    "github.com/CS-SI/SafeScale/lib/client"
    "github.com/CS-SI/SafeScale/lib/server/utils"
    app2 "github.com/CS-SI/SafeScale/lib/utils/app"
    "github.com/CS-SI/SafeScale/lib/utils/debug"
    "github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
    "github.com/CS-SI/SafeScale/lib/utils/temporal"

    // Autoload embedded provider drivers
    _ "github.com/CS-SI/SafeScale/lib/server"
)

var profileCloseFunc = func() {}

func cleanup(clientSession *client.Session, onAbort bool) {
    if onAbort {
        fmt.Println("\nBe careful stopping safescale will not stop the job on safescaled, but will try to go back to the previous state as much as possible!")
        reader := bufio.NewReader(os.Stdin)
        fmt.Print("Do you really want to stop the command ? [y]es [n]o: ")
        text, err := reader.ReadString('\n')
        if err != nil {
            fmt.Println("failed to read the input : ", err.Error())
            text = "y"
        }
        if strings.TrimRight(text, "\n") == "y" {
            err = clientSession.JobManager.Stop(utils.GetUUID(), temporal.GetExecutionTimeout())
            if err != nil {
                fmt.Printf("failed to stop the process %v\n", err)
            }
        }
    }
    profileCloseFunc()
    os.Exit(0)
}

func main() {
    runtime.GOMAXPROCS(runtime.NumCPU())

    var (
        onAbort       bool
        clientSession *client.Session
    )

    mainCtx, cancelfunc := context.WithCancel(context.Background())

    app := cli.NewApp()
    app.Writer = os.Stderr
    app.Name = "safescale"
    app.Usage = "safescale COMMAND"
    app.Version = Version + ", build " + Revision + " compiled with " + runtime.Version() + " (" + BuildDate + ")"
    app.Authors = []*cli.Author{
        {
            Name:  "CS-SI",
            Email: "safescale@c-s.fr",
        },
    }

    app.EnableBashCompletion = true

    cli.VersionFlag = &cli.BoolFlag{
        Name:    "version",
        Aliases: []string{"V"},
        Usage:   "Print program version",
    }

    app.Flags = []cli.Flag{
        &cli.BoolFlag{
            Name:    "verbose",
            Aliases: []string{"v"},
            Usage:   "Increase verbosity",
        },
        &cli.BoolFlag{
            Name:    "debug",
            Aliases: []string{"d"},
            Usage:   "Show debug information",
        },
        &cli.StringFlag{
            Name:  "profile",
            Usage: "Profiles binary; can contain 'cpu', 'ram', 'web' and a combination of them (ie 'cpu,ram')",
            // TODO: extends profile to accept <what>:params, for example cpu:$HOME/safescale.cpu.pprof, or web:192.168.2.1:1666
        },
        &cli.StringFlag{
            Name:    "server",
            Aliases: []string{"S"},
            Usage:   "Connect to daemon on server SERVER (default: localhost:50051)",
            Value:   "",
        },
        &cli.StringFlag{
            Name:    "tenant",
            Aliases: []string{"T"},
            Usage:   "Use tenant TENANT (default: none)",
        },
    }

    app.Before = func(c *cli.Context) error {
        // Define trace settings of the application (what to trace if trace is wanted)
        // TODO: is it the good behavior ? Shouldn't we fail ?
        // If trace settings cannot be registered, report it but do not fail
        err := tracing.RegisterTraceSettings(appTrace)
        if err != nil {
            logrus.Errorf(err.Error())
        }

        // Sets profiling
        if c.IsSet("profile") {
            what := c.String("profile")
            profileCloseFunc = debug.Profile(what)
        }

        if strings.Contains(path.Base(os.Args[0]), "-cover") {
            logrus.SetLevel(logrus.TraceLevel)
            app2.Verbose = true
        } else {
            logrus.SetLevel(logrus.WarnLevel)
        }

        // Defines trace level wanted by user
        if app2.Verbose = c.Bool("verbose"); app2.Verbose {
            logrus.SetLevel(logrus.InfoLevel)
            app2.Verbose = true
        }
        if app2.Debug = c.Bool("debug"); app2.Debug {
            if app2.Verbose {
                logrus.SetLevel(logrus.TraceLevel)
            } else {
                logrus.SetLevel(logrus.DebugLevel)
            }
        }

        clientSession, err = client.New(c.String("server"))
        return err
    }

    app.After = func(c *cli.Context) error {
        cleanup(clientSession, onAbort)
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

    app.Commands = append(app.Commands, commands.SecurityGroupCommand)
    sort.Sort(cli.CommandsByName(commands.SecurityGroupCommand.Subcommands))

    sort.Sort(cli.CommandsByName(app.Commands))

    // Starts ctrl+c handler before app.RunContext()
    c := make(chan os.Signal)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        for {
            <-c
            onAbort = true
            cancelfunc()
        }
    }()

    err := app.RunContext(mainCtx, os.Args)
    if err != nil {
        fmt.Println("Error Running App : " + err.Error())
    }
}
