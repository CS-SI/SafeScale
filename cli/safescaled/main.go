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
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/listeners"
	"github.com/CS-SI/SafeScale/lib/server/utils"

	_ "github.com/CS-SI/SafeScale/lib/server"
)

func cleanup() {
	fmt.Println("cleanup")
}

// *** MAIN ***
func work() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cleanup()
		exit.Exit(1)
	}()

	log.Infoln("Checking configuration")
	_, err := iaas.GetTenantNames()
	if err != nil {
		log.Fatalf(err.Error())
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
			log.Infof("Using %s", envVar)
		}
	}

	log.Infof("Starting server, listening at port: %d, using metadata suffix: [%s]", safescaledPort, suffix)

	lis, err := net.Listen("tcp", ":"+strconv.Itoa(safescaledPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	log.Infoln("Registering services")
	pb.RegisterBucketServiceServer(s, &listeners.BucketListener{})
	pb.RegisterDataServiceServer(s, &listeners.DataListener{})
	pb.RegisterHostServiceServer(s, &listeners.HostListener{})
	pb.RegisterImageServiceServer(s, &listeners.ImageListener{})
	pb.RegisterJobManagerServiceServer(s, &listeners.JobManagerListener{})
	pb.RegisterNetworkServiceServer(s, &listeners.NetworkListener{})
	pb.RegisterShareServiceServer(s, &listeners.ShareListener{})
	pb.RegisterSshServiceServer(s, &listeners.SSHListener{})
	pb.RegisterTemplateServiceServer(s, &listeners.TemplateListener{})
	pb.RegisterTenantServiceServer(s, &listeners.TenantListener{})
	pb.RegisterVolumeServiceServer(s, &listeners.VolumeListener{})

	// log.Println("Initializing service factory")
	// commands.InitServiceFactory()

	// Register reflection service on gRPC server.
	reflection.Register(s)

	version := VERSION + ", build " + REV + " (" + BUILD_DATE + ")"
	fmt.Printf("Safescaled version: %s\nReady to serve :-)\n", version)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	app := cli.NewApp()
	app.Name = "safescaled"
	app.Usage = "safescaled [OPTIONS]"
	app.Version = VERSION + ", build " + REV + " (" + BUILD_DATE + ")"

	app.Authors = []cli.Author{
		cli.Author{
			Name:  "CS-SI",
			Email: "safescale@c-s.fr",
		},
	}
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

	app.Action = func(c *cli.Context) error {
		work()
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
