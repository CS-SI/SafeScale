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

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/listeners"
	"github.com/CS-SI/SafeScale/lib/server/utils"
)

/*
safescale provider list
safescale provider sample p1

safescale tenant add ovh1 --provider="OVH" --config="ovh1.json"
safescale tenant list
safescale tenant get ovh1
safescale tenant set ovh1

safescale network create net1 --cidr="192.145.0.0/16" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" (par défault "192.168.0.0/24", on crée une gateway sur chaque réseau: gw_net1)
safescale network list
safescale network delete net1
safescale network inspect net1

safescale host create host1 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=true
safescale host list
safescale host inspect host1
safescale host create host2 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=false

safescale ssh connect host2
safescale ssh run host2 -c "uname -a"
safescale ssh copy /file/test.txt host1://tmp
safescale ssh copy host1:/file/test.txt /tmp

safescale volume create v1 --speed="SSD" --size=2000 (par default HDD, possible SSD, HDD, COLD)
safescale volume attach v1 host1 --path="/shared/data" --format="xfs" (par default /shared/v1 et ext4)
safescale volume detach v1
safescale volume delete v1
safescale volume inspect v1
safescale volume update v1 --speed="HDD" --size=1000

safescale bucket|container create c1
safescale bucket|container mount c1 host1 --path="/shared/data" (utilisation de s3ql, par default /containers/c1)
safescale bucket|container umount c1 host1
safescale bucket|container delete c1
safescale bucket|container list
safescale bucket|container inspect C1

safescale share|nas create nas1 host1 --path="/shared/data"
safescale share|nas delete nas1
safescale share|nas mount nas1 host2 --path="/data"
safescale share|nas umount nas1 host2
safescale share|nas list
safescale share|nas inspect nas1

*/

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
	pb.RegisterNetworkServiceServer(s, &listeners.NetworkListener{})
	pb.RegisterProcessManagerServiceServer(s, &listeners.ProcessManagerListener{})
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

	app.Action = func(c *cli.Context) error {
		work()
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
