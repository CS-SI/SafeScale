package main

import (
	"log"
	"net"

	pb "github.com/SafeScale/broker"
	"github.com/SafeScale/broker/brokerd/commands"
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

broker vm create vm1 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=true
broker vm list
broker vm inspect vm1
broker vm create vm2 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=false

broker ssh connect vm2
broker ssh run vm2 -c "uname -a"
broker ssh copy /file/test.txt vm1://tmp
broker ssh copy vm1:/file/test.txt /tmp

broker volume create v1 --speed="SSD" --size=2000 (par default HDD, possible SSD, HDD, COLD)
broker volume attach v1 vm1 --path="/shared/data" --format="xfs" (par default /shared/v1 et ext4)
broker volume detach v1
broker volume delete v1
broker volume inspect v1
broker volume update v1 --speed="HDD" --size=1000

broker container create c1
broker container mount c1 vm1 --path="/shared/data" (utilisation de s3ql, par default /containers/c1)
broker container umount c1 vm1
broker container delete c1
broker container list
broker container inspect C1

broker nas create nas1 vm1 --path="/shared/data"
broker nas delete nas1
broker nas mount nas1 vm2 --path="/data"
broker nas umount nas1 vm2
broker nas list
broker nas inspect nas1

*/

// *** MAIN ***
func main() {
	log.Println("Starting server")
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	log.Println("Registering services")
	pb.RegisterTenantServiceServer(s, &commands.TenantServiceServer{})
	pb.RegisterNetworkServiceServer(s, &commands.NetworkServiceServer{})
	pb.RegisterVMServiceServer(s, &commands.VMServiceServer{})
	pb.RegisterVolumeServiceServer(s, &commands.VolumeServiceServer{})
	pb.RegisterSshServiceServer(s, &commands.SSHServiceServer{})
	pb.RegisterContainerServiceServer(s, &commands.ContainerServiceServer{})

	log.Println("Initializing service factory")
	commands.InitServiceFactory()

	// Register reflection service on gRPC server.
	reflection.Register(s)
	log.Println("Ready to serve :-)")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
