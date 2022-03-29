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
	"fmt"
	"net"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/makholm/covertool/pkg/exit"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	_ "github.com/CS-SI/SafeScale/v21/lib/server"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v21/lib/server/listeners"
	appwide "github.com/CS-SI/SafeScale/v21/lib/utils/app"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/heartbeat"
)

var profileCloseFunc = func() {}

const (
	defaultDaemonHost string = "localhost" // By default, safescaled only listen on localhost
	defaultDaemonPort string = "50051"
)

func cleanup(onAbort bool) {
	if onAbort {
		fmt.Println("Cleaning up...")
	}
	profileCloseFunc()
	exit.Exit(1)
}

// *** MAIN ***
func work(c *cli.Context) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		var crash error
		defer fail.OnPanic(&crash)

		<-signalCh
		cleanup(true)
	}()

	// NOTE: is it the good behavior ? Shouldn't we fail ?
	// If trace settings cannot be registered, report it but do not fail
	// TODO: introduce use of configuration file with autoreload on change
	err := tracing.RegisterTraceSettings(appTrace())
	if err != nil {
		logrus.Errorf(err.Error())
	}

	logrus.Infoln("Checking configuration")
	_, err = iaas.GetTenantNames()
	if err != nil {
		logrus.Fatalf(err.Error())
	}

	listen := assembleListenString(c)

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

	logrus.Infof("Starting server, listening on '%s', using metadata suffix '%s'", listen, suffix)
	lis, err := net.Listen("tcp", listen)
	if err != nil {
		logrus.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	logrus.Infoln("Registering services")
	protocol.RegisterBucketServiceServer(s, &listeners.BucketListener{})
	protocol.RegisterClusterServiceServer(s, &listeners.ClusterListener{})
	protocol.RegisterHostServiceServer(s, &listeners.HostListener{})
	protocol.RegisterFeatureServiceServer(s, &listeners.FeatureListener{})
	protocol.RegisterImageServiceServer(s, &listeners.ImageListener{})
	protocol.RegisterJobServiceServer(s, &listeners.JobManagerListener{})
	protocol.RegisterNetworkServiceServer(s, &listeners.NetworkListener{})
	protocol.RegisterSubnetServiceServer(s, &listeners.SubnetListener{})
	protocol.RegisterSecurityGroupServiceServer(s, &listeners.SecurityGroupListener{})
	protocol.RegisterShareServiceServer(s, &listeners.ShareListener{})
	protocol.RegisterSshServiceServer(s, &listeners.SSHListener{})
	protocol.RegisterTemplateServiceServer(s, &listeners.TemplateListener{})
	protocol.RegisterTenantServiceServer(s, &listeners.TenantListener{})
	protocol.RegisterVolumeServiceServer(s, &listeners.VolumeListener{})

	// enable heartbeat
	go heartbeat.RunHeartbeatService(":10102")

	// Register reflection service on gRPC server.
	reflection.Register(s)

	// Track goroutines
	startTrack()
	defer endTrack()

	// Expose runtime
	// - /debug/vars
	// - /debug/metrics
	// - /debug/fgprof
	expose()

	// operations.StartFeatureFileWatcher()

	version := Version + ", build " + Revision + " (" + BuildDate + ")"
	if              //goland:noinspection GoBoolExpressions
	len(Tags) > 1 { // nolint
		version += fmt.Sprintf(", with Tags: (%s)", Tags)
	}
	fmt.Printf("Safescaled version: %s\nReady to serve on '%s' :-)\n", version, listen)
	if err := s.Serve(lis); err != nil {
		logrus.Fatalf("Failed to serve: %v", err)
	}
}

// assembleListenString constructs the listen string we will use in net.Listen()
func assembleListenString(c *cli.Context) string {
	// Get listen from parameters
	listen := c.String("listen")
	if listen == "" {
		listen = os.Getenv("SAFESCALED_LISTEN")
	}
	if listen != "" {
		// Validate port part of the content of listen...
		parts := strings.Split(listen, ":")
		switch len(parts) {
		case 1:
			listen = parts[0] + ":" + defaultDaemonPort
		case 2:
			num, err := strconv.Atoi(parts[1])
			if err != nil || num <= 0 {
				logrus.Warnf("Parameter 'listen' content is invalid (port cannot be '%s'): ignored.", parts[1])
			}
		default:
			logrus.Warnf("Parameter 'listen' content is invalid, ignored.")
		}
	}
	// if listen is empty, get the port from env
	if listen == "" {
		if port := os.Getenv("SAFESCALED_PORT"); port != "" {
			num, err := strconv.Atoi(port)
			if err != nil || num <= 0 {
				logrus.Warnf("Environment variable 'SAFESCALED_PORT' contains invalid content ('%s'): ignored.", port)
			} else {
				listen = defaultDaemonHost + ":" + port
			}
		}

		// At last, if listen is empty, build it from defaults
		if listen == "" {
			listen = defaultDaemonHost + ":" + defaultDaemonPort
		}
	}

	return listen
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	app := cli.NewApp()
	app.Name = "safescaled"
	app.Usage = "safescaled [OPTIONS]"
	app.Version = Version + ", build " + Revision + " compiled with " + runtime.Version() + " (" + BuildDate + ")"

	app.Authors = []*cli.Author{
		{
			Name:  "CS-SI",
			Email: "safescale@csgroup.eu",
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
			Name: "profile",
			Usage: `Profiles binary
            value is a comma-separated list of <keyword> (ie '<keyword>[:<params>][,<keyword>[:<params>]...]) where <keyword>
            can be 'cpu', 'ram', 'trace', and 'web'.
            <params> may contain :
                for 'ram', 'cpu' and 'trace': optional destination folder of output file (default: current working directory)
                for 'web': [<listen addr>][:<listen port>] (default: 'localhost:6060')`,
		},
		&cli.StringFlag{
			Name:    "listen",
			Aliases: []string{"l"},
			Usage:   "Listen on specified port `IP:PORT` (default: localhost:50051)",
		},
	}

	app.Before = func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		// Sets profiling
		if c.IsSet("profile") {
			what := c.String("profile")
			profileCloseFunc = debug.Profile(what)
		}

		if strings.Contains(path.Base(os.Args[0]), "-cover") {
			logrus.SetLevel(logrus.TraceLevel)
			appwide.Verbose = true
		} else {
			logrus.SetLevel(logrus.WarnLevel)
		}

		// default level is INFO
		logrus.SetLevel(logrus.InfoLevel)

		// if -d or -v specified -> DEBUG Level
		if c.Bool("verbose") {
			logrus.SetLevel(logrus.InfoLevel)
			appwide.Verbose = true
		}

		if c.Bool("debug") {
			if c.Bool("verbose") {
				logrus.SetLevel(logrus.TraceLevel)
			} else {
				logrus.SetLevel(logrus.DebugLevel)
			}
			appwide.Debug = true
		}

		// if -d AND -v specified -> TRACE Level
		if c.Bool("debug") && c.Bool("verbose") {
			logrus.SetLevel(logrus.TraceLevel)
			appwide.Verbose = true
			appwide.Debug = true
		}
		return nil
	}

	app.Action = func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		work(c)
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		logrus.Error(err)
	}

	cleanup(false)
}
