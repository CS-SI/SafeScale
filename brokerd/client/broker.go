package main

import (
	"fmt"
	"log"
	"os"
	"time"

	pb "github.com/SafeScale/brokerd"
	cli "github.com/urfave/cli"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	address = "localhost:50051"
)

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// CLI Flags
	app := cli.NewApp()
	app.Name = "broker"
	app.Usage = "broker COMMAND"
	app.Version = "0.0.1"
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "CS-SI",
			Email: "safescale@c-s.fr",
		},
	}
	app.EnableBashCompletion = true
	app.Commands = []cli.Command{
		{
			Name:  "network",
			Usage: "network COMMAND",
			Subcommands: []cli.Command{
				{
					Name:  "list",
					Usage: "list TENANT_NAME",
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Missing mandatory argument <tenant_name>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("Tenant name required")
						}

						// Network
						networkService := pb.NewNetworkServiceClient(conn)
						networks, err := networkService.List(ctx, &pb.TenantName{Name: c.Args().First()})
						if err != nil {
							log.Fatalf("could not get network list: %v", err)
						}
						for i, network := range networks.GetNetworks() {
							// log.Printf("Network %d: %s", i, network)
							fmt.Printf("Network %d: %s", i, network)
						}

						return nil
					},
				},
				{
					Name:      "delete",
					Usage:     "delete NETWORK",
					ArgsUsage: "<network_name>",
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Missing mandatory argument <network_name>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("Network name required")
						}

						// Network
						networkService := pb.NewNetworkServiceClient(conn)
						_, err := networkService.Delete(ctx, &pb.Reference{Name: c.Args().First(), TenantID: "TestOvh"})
						if err != nil {
							log.Fatalf("could not delete network %s: %v", c.Args().First(), err)
						}
						fmt.Printf("Network %s deleted", c.Args().First())

						return nil
					},
				},
				{
					Name:      "create",
					Usage:     "create a network",
					ArgsUsage: "<network_name>",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "cidr",
							Value: "192.168.0.0/24",
							Usage: "cidr of the network",
						},
						cli.IntFlag{
							Name:  "cpu",
							Value: 1,
							Usage: "Number of CPU for the gateway",
						},
						cli.Float64Flag{
							Name:  "ram",
							Value: 1,
							Usage: "RAM for the gateway",
						},
						cli.IntFlag{
							Name:  "disk",
							Value: 100,
							Usage: "Disk space for the gateway",
						},
						cli.StringFlag{
							Name:  "os",
							Value: "Ubuntu 16.04",
							Usage: "Image name for the gateway",
						}},
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Missing mandatory argument <network_name>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("Network name reqired")
						}
						fmt.Println("create network: ", c.Args().First(), c.String("cidr"), c.Int("ram"))
						// Network
						networkService := pb.NewNetworkServiceClient(conn)
						netdef := &pb.NetworkDefinition{
							CIDR:   c.String("cidr"),
							Name:   c.Args().Get(0),
							Tenant: "TestOvh",
							Gateway: &pb.GatewayDefinition{
								CPU:  int32(c.Int("cpu")),
								Disk: int32(c.Int("disk")),
								RAM:  float32(c.Float64("ram")),
								// CPUFrequency: ??,
								ImageID: c.String("os"),
							},
						}
						network, err := networkService.Create(ctx, netdef)
						if err != nil {
							log.Fatalf("could not get network list: %v", err)
						}
						fmt.Printf("Network: %s", network)

						return nil
					},
				},
			},
		},
	}
	_ = app.Run(os.Args)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// var name string
	// // broker tenant list
	// if len(os.Args) > 1 {
	// 	name = os.Args[1]
	// 	fmt.Printf("param : %s", name)
	// }

	// // Image
	// imageService := pb.NewImageServiceClient(conn)
	// r, err := imageService.List(ctx, &pb.Reference{})
	// if err != nil {
	// 	log.Fatalf("could not get image list: %v", err)
	// }

	// for i, image := range r.GetImages() {
	// 	log.Printf("Image %d: %s", i, image)
	// }

	// // Tenant
	// tenantService := pb.NewTenantServiceClient(conn)
	// tenants, err := tenantService.List(ctx, &pb.Empty{})
	// if err != nil {
	// 	log.Fatalf("could not get tenant list: %v", err)
	// }

	// for i, tenant := range tenants.GetTenants() {
	// 	log.Printf("Tenant %d: %s", i, tenant)
	// }

	// // Network
	// networkService := pb.NewNetworkServiceClient(conn)
	// networks, err := networkService.List(ctx, &pb.TenantName{Name: "TestOvh"})
	// // networks, err := networkService.ListNetwork(ctx, &pb.TenantName{Name: "TestCloudwatt"})
	// if err != nil {
	// 	log.Fatalf("could not get network list: %v", err)
	// }
	// for i, network := range networks.GetNetworks() {
	// 	log.Printf("Network %d: %s", i, network)
	// }
}
