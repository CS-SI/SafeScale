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
	"fmt"
	"net"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/dlespiau/covertool/pkg/exit"
	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/listeners"
	"github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/debug"

	_ "github.com/CS-SI/SafeScale/lib/server"
)

var profileCloseFunc = func() {}

func cleanup(onAbort bool) {
	fmt.Println("cleanup")
	profileCloseFunc()
	exit.Exit(1)
}

// *** MAIN ***
func work() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cleanup(true)
	}()

	// NOTE: is it the good behavior ? Shouldn't we fail ?
	// If trace settings cannot be registered, report it but do not fail
	err := debug.RegisterTraceSettings(appTrace)
	if err != nil {
		logrus.Errorf(err.Error())
	}

	logrus.Infoln("Checking configuration")
	_, err = iaas.GetTenantNames()
	if err != nil {
		logrus.Fatalf(err.Error())
	}

	safescaledPort := 50051

	// DEV VAR
	if portCandidate := os.Getenv("SAFESCALED_PORT"); portCandidate != "" {
		num, err := strconv.Atoi(portCandidate)
		if err == nil {
			safescaledPort = num
		}
	}

	// DEV VAR
	suffix := ""
	if suffixCandidate := os.Getenv("SAFESCALE_METADATA_SUFFIX"); suffixCandidate != "" {
		suffix = suffixCandidate
	}

	envVars := os.Environ()
	for _, envVar := range envVars {
		if strings.HasPrefix(envVar, "SAFESCALE") {
			logrus.Infof("Using %s", envVar)
		}
	}

	logrus.Infof("Starting server, listening at port: %d, using metadata suffix: [%s]", safescaledPort, suffix)
	lis, err := net.Listen("tcp", ":"+strconv.Itoa(safescaledPort))
	if err != nil {
		logrus.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	logrus.Infoln("Registering services")
	protocol.RegisterBucketServiceServer(s, &listeners.BucketListener{})
	// pb.RegisterDataServiceServer(s, &listeners.DataListener{})
	protocol.RegisterHostServiceServer(s, &listeners.HostListener{})
	protocol.RegisterImageServiceServer(s, &listeners.ImageListener{})
	protocol.RegisterJobServiceServer(s, &listeners.JobManagerListener{})
	protocol.RegisterNetworkServiceServer(s, &listeners.NetworkListener{})
	protocol.RegisterShareServiceServer(s, &listeners.ShareListener{})
	protocol.RegisterSshServiceServer(s, &listeners.SSHListener{})
	protocol.RegisterTemplateServiceServer(s, &listeners.TemplateListener{})
	protocol.RegisterTenantServiceServer(s, &listeners.TenantListener{})
	protocol.RegisterVolumeServiceServer(s, &listeners.VolumeListener{})

	// log.Println("Initializing service factory")
	// commands.InitServiceFactory()

	// Register reflection service on gRPC server.
	reflection.Register(s)

	version := Version + ", build " + Revision + " (" + BuildDate + ")"
	fmt.Printf("Safescaled version: %s\nReady to serve :-)\n", version)
	if err := s.Serve(lis); err != nil {
		logrus.Fatalf("Failed to serve: %v", err)
	}
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	app := cli.NewApp()
	app.Name = "safescaled"
	app.Usage = "safescaled [OPTIONS]"
	app.Version = Version + ", build " + Revision + " (" + BuildDate + ")"

	app.Authors = []*cli.Author{
		&cli.Author{
			Name:  "CS-SI",
			Email: "safescale@c-s.fr",
		},
	}
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
		// &cli.IntFlag{
		// 	Name:  "port",
		// 	Aliases: []string{"p"},
		// 	Usage: "Bind to specified port `PORT`",
		// 	Value: 50051,
		// },
	}

	app.Before = func(c *cli.Context) error {
		// Sets profiling
		if c.IsSet("profile") {
			what := c.String("profile")
			profileCloseFunc = debug.Profile(what)
		}

		if strings.Contains(path.Base(os.Args[0]), "-cover") {
			logrus.SetLevel(logrus.TraceLevel)
			utils.Verbose = true
		} else {
			logrus.SetLevel(logrus.WarnLevel)
		}

		if c.Bool("verbose") {
			logrus.SetLevel(logrus.InfoLevel)
			utils.Verbose = true
		}
		if c.Bool("debug") {
			if c.Bool("verbose") {
				logrus.SetLevel(logrus.TraceLevel)
			} else {
				logrus.SetLevel(logrus.DebugLevel)
			}
			utils.Debug = true
		}
		return nil
	}

	app.Action = func(c *cli.Context) error {
		work()
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		logrus.Error(err)
	}

	cleanup(false)
}
