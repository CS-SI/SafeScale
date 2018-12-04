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
	"fmt"
	"net"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/dlespiau/covertool/pkg/exit"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/server/listeners"
	"github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/providers"
)

/*
broker provider list
broker provider sample p1

broker tenant add ovh1 --provider="OVH" --config="ovh1.json"
broker tenant list
broker tenant get ovh1
broker tenant set ovh1

broker network create net1 --cidr="192.145.0.0/16" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" (par défault "192.168.0.0/24", on crée une gateway sur chaque réseau: gw_net1)
broker network list
broker network delete net1
broker network inspect net1

broker host create host1 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=true
broker host list
broker host inspect host1
broker host create host2 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=false

broker ssh connect host2
broker ssh run host2 -c "uname -a"
broker ssh copy /file/test.txt host1://tmp
broker ssh copy host1:/file/test.txt /tmp

broker volume create v1 --speed="SSD" --size=2000 (par default HDD, possible SSD, HDD, COLD)
broker volume attach v1 host1 --path="/shared/data" --format="xfs" (par default /shared/v1 et ext4)
broker volume detach v1
broker volume delete v1
broker volume inspect v1
broker volume update v1 --speed="HDD" --size=1000

broker bucket|container create c1
broker bucket|container mount c1 host1 --path="/shared/data" (utilisation de s3ql, par default /containers/c1)
broker bucket|container umount c1 host1
broker bucket|container delete c1
broker bucket|container list
broker bucket|container inspect C1

broker share|nas create nas1 host1 --path="/shared/data"
broker share|nas delete nas1
broker share|nas mount nas1 host2 --path="/data"
broker share|nas umount nas1 host2
broker share|nas list
broker share|nas inspect nas1

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
	_, err := providers.Tenants()
	if err != nil {
		log.Fatalf(err.Error())
	}

	brokerdPort := 50051

	if portCandidate := os.Getenv("BROKERD_PORT"); portCandidate != "" {
		num, err := strconv.Atoi(portCandidate)
		if err == nil {
			brokerdPort = num
		}
	}

	log.Infof("Starting server, listening at port: %d", brokerdPort)

	lis, err := net.Listen("tcp", ":" + strconv.Itoa(brokerdPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	log.Infoln("Registering services")
	pb.RegisterTenantServiceServer(s, &listeners.TenantListener{})
	pb.RegisterNetworkServiceServer(s, &listeners.NetworkListener{})
	pb.RegisterHostServiceServer(s, &listeners.HostListener{})
	pb.RegisterVolumeServiceServer(s, &listeners.VolumeListener{})
	pb.RegisterSshServiceServer(s, &listeners.SSHListener{})
	pb.RegisterBucketServiceServer(s, &listeners.BucketListener{})
	pb.RegisterShareServiceServer(s, &listeners.ShareListener{})
	pb.RegisterImageServiceServer(s, &listeners.ImageListener{})
	pb.RegisterTemplateServiceServer(s, &listeners.TemplateListener{})

	// log.Println("Initializing service factory")
	// commands.InitServiceFactory()

	// Register reflection service on gRPC server.
	reflection.Register(s)

	version := VERSION + ", build date: " + BUILD_DATE + "-" + REV
	fmt.Printf("Brokerd version: %s\nReady to serve :-)\n", version)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

func main() {
	app := cli.NewApp()

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
			log.SetLevel(log.InfoLevel)
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
