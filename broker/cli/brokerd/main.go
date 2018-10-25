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
	"github.com/dlespiau/covertool/pkg/exit"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/daemon/commands"

	"github.com/CS-SI/SafeScale/providers"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	port = ":50051"
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

broker container create c1
broker container mount c1 host1 --path="/shared/data" (utilisation de s3ql, par default /containers/c1)
broker container umount c1 host1
broker container delete c1
broker container list
broker container inspect C1

broker nas create nas1 host1 --path="/shared/data"
broker nas delete nas1
broker nas mount nas1 host2 --path="/data"
broker nas umount nas1 host2
broker nas list
broker nas inspect nas1

*/

func cleanup() {
	fmt.Println("cleanup")
}

// *** MAIN ***
func main() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cleanup()
		exit.Exit(1)
	}()

	log.Println("Checking configuration")
	_, err := providers.Tenants()
	if err != nil {
		log.Fatalf(err.Error())
	}

	log.Println("Starting server")
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	log.Println("Registering services")
	pb.RegisterTenantServiceServer(s, &commands.TenantServiceServer{})
	pb.RegisterNetworkServiceServer(s, &commands.NetworkServiceServer{})
	pb.RegisterHostServiceServer(s, &commands.HostServiceServer{})
	pb.RegisterVolumeServiceServer(s, &commands.VolumeServiceServer{})
	pb.RegisterSshServiceServer(s, &commands.SSHServiceServer{})
	pb.RegisterContainerServiceServer(s, &commands.ContainerServiceServer{})
	pb.RegisterNasServiceServer(s, &commands.NasServiceServer{})
	pb.RegisterImageServiceServer(s, &commands.ImageServiceServer{})
	pb.RegisterTemplateServiceServer(s, &commands.TemplateServiceServer{})

	// log.Println("Initializing service factory")
	// commands.InitServiceFactory()

	// Register reflection service on gRPC server.
	reflection.Register(s)

	version := VERSION + "-" + BUILD_DATE
	log.Printf("Brokerd version: %s", version)
	log.Println("Ready to serve :-)")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
