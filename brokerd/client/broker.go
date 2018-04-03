package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	conv "github.com/SafeScale/broker/commands"
	pb "github.com/SafeScale/brokerd"
	cli "github.com/urfave/cli"
	context "golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	address           = "localhost:50051"
	timeoutCtxDefault = 10 * time.Second
	timeoutCtxVM      = 2 * time.Minute
)

func getConnection() *grpc.ClientConn {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	return conn
}

func getContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	// Contact the server and print out its response.
	return context.WithTimeout(context.Background(), timeout)
}

func main() {

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
					Usage: "list",
					Action: func(c *cli.Context) error {
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						networkService := pb.NewNetworkServiceClient(conn)
						networks, err := networkService.List(ctx, &pb.Empty{})
						if err != nil {
							return fmt.Errorf("Could not get network list: %v", err)
						}
						out, _ := json.Marshal(networks.GetNetworks())
						fmt.Println(string(out))

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
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						networkService := pb.NewNetworkServiceClient(conn)
						_, err := networkService.Delete(ctx, &pb.Reference{Name: c.Args().First(), TenantID: "TestOvh"})
						if err != nil {
							return fmt.Errorf("Could not delete network %s: %v", c.Args().First(), err)
						}
						fmt.Println(fmt.Sprintf("Network '%s' deleted", c.Args().First()))

						return nil
					},
				},
				{
					Name:      "inspect",
					Usage:     "inspect NETWORK",
					ArgsUsage: "<network_name>",
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Missing mandatory argument <network_name>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("Network name required")
						}

						// Network
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						networkService := pb.NewNetworkServiceClient(conn)
						network, err := networkService.Inspect(ctx, &pb.Reference{Name: c.Args().First(), TenantID: "TestOvh"})
						if err != nil {
							return fmt.Errorf("Could not inspect network %s: %v", c.Args().First(), err)
						}
						out, _ := json.Marshal(network)
						fmt.Println(string(out))

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
						// Network
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxVM)
						defer cancel()
						networkService := pb.NewNetworkServiceClient(conn)
						netdef := &pb.NetworkDefinition{
							CIDR: c.String("cidr"),
							Name: c.Args().Get(0),
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
							return fmt.Errorf("Could not get network list: %v", err)
						}
						out, _ := json.Marshal(network)
						fmt.Println(string(out))

						return nil
					},
				},
			},
		},
		{
			Name:  "tenant",
			Usage: "tenant COMMAND",
			Subcommands: []cli.Command{
				{
					Name:  "list",
					Usage: "List available tenants",
					Action: func(c *cli.Context) error {
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						tenantService := pb.NewTenantServiceClient(conn)
						tenants, err := tenantService.List(ctx, &pb.Empty{})
						if err != nil {
							return fmt.Errorf("Could not get tenant list: %v", err)
						}
						out, _ := json.Marshal(tenants.GetTenants())
						fmt.Println(string(out))

						return nil
					},
				},
				{
					Name:  "get",
					Usage: "Get current tenant",
					Action: func(c *cli.Context) error {
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						tenantService := pb.NewTenantServiceClient(conn)
						tenant, err := tenantService.Get(ctx, &pb.Empty{})
						if err != nil {
							return fmt.Errorf("Could not get current tenant: %v", err)
						}
						out, _ := json.Marshal(tenant)
						fmt.Println(string(out))

						return nil
					},
				},
				{
					Name:      "set",
					Usage:     "Set tenant to work with",
					ArgsUsage: "<tenant_name>",
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Missing mandatory argument <tenant_name>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("Tenant name required")
						}
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						tenantService := pb.NewTenantServiceClient(conn)
						_, err := tenantService.Set(ctx, &pb.TenantName{Name: c.Args().First()})
						if err != nil {
							return fmt.Errorf("Could not get current tenant: %v", err)
						}
						fmt.Printf("Tenant '%s' set", c.Args().First())

						return nil
					},
				},
			}}, {
			Name:  "vm",
			Usage: "vm COMMAND",
			Subcommands: []cli.Command{
				{
					Name:  "list",
					Usage: "List available VMs",
					Action: func(c *cli.Context) error {
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						service := pb.NewVMServiceClient(conn)
						vms, err := service.List(ctx, &pb.Empty{})
						if err != nil {
							return fmt.Errorf("Could not get vm list: %v", err)
						}
						out, _ := json.Marshal(vms.GetVMs())
						fmt.Println(string(out))

						return nil
					},
				},
				{
					Name:      "inspect",
					Usage:     "inspect VM",
					ArgsUsage: "<VM_name|VM_ID>",
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Missing mandatory argument <VM_name>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("VM name or ID required")
						}
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						service := pb.NewVMServiceClient(conn)
						resp, err := service.Inspect(ctx, &pb.Reference{Name: c.Args().First()})
						if err != nil {
							return fmt.Errorf("Could not inspect vm '%s': %v", c.Args().First(), err)
						}

						out, _ := json.Marshal(resp)
						fmt.Println(string(out))

						return nil
					},
				}, {
					Name:      "create",
					Usage:     "create a new VM",
					ArgsUsage: "<VM_name>",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "net",
							Usage: "Name or ID of the network to put the VM on",
						},
						cli.IntFlag{
							Name:  "cpu",
							Value: 1,
							Usage: "Number of CPU for the VM",
						},
						cli.Float64Flag{
							Name:  "ram",
							Value: 1,
							Usage: "RAM for the VM",
						},
						cli.IntFlag{
							Name:  "disk",
							Value: 100,
							Usage: "Disk space for the VM",
						},
						cli.StringFlag{
							Name:  "os",
							Value: "Ubuntu 16.04",
							Usage: "Image name for the VM",
						},
						cli.BoolTFlag{
							Name:  "public",
							Usage: "Public IP",
						},
						cli.BoolFlag{
							Name:   "gpu",
							Usage:  "With GPU",
							Hidden: true,
						},
					},
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Missing mandatory argument <VM_name>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("VM name required")
						}
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxVM)
						defer cancel()
						service := pb.NewVMServiceClient(conn)
						resp, err := service.Create(ctx, &pb.VMDefinition{
							Name:      c.Args().First(),
							CPUNumber: int32(c.Int("cpu")),
							Disk:      int32(c.Float64("disk")),
							ImageID:   c.String("os"),
							Network:   c.String("net"),
							Public:    c.BoolT("public"),
							RAM:       float32(c.Float64("ram")),
						})
						if err != nil {
							return fmt.Errorf("Could not create vm '%s': %v", c.Args().First(), err)
						}

						out, _ := json.Marshal(resp)
						fmt.Println(string(out))

						return nil
					},
				}, {
					Name:      "delete",
					Usage:     "Delete VM",
					ArgsUsage: "<VM_name|VM_ID>",
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Missing mandatory argument <VM_name>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("VM name or ID required")
						}
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						service := pb.NewVMServiceClient(conn)
						_, err := service.Delete(ctx, &pb.Reference{Name: c.Args().First()})
						if err != nil {
							return fmt.Errorf("Could not delete vm '%s': %v", c.Args().First(), err)
						}
						fmt.Println(fmt.Sprintf("VM '%s' deleted", c.Args().First()))
						return nil
					},
				}, {
					Name:      "ssh",
					Usage:     "Get ssh config to connect to VM",
					ArgsUsage: "<VM_name|VM_ID>",
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Missing mandatory argument <VM_name>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("VM name or ID required")
						}
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						service := pb.NewVMServiceClient(conn)
						resp, err := service.Ssh(ctx, &pb.Reference{Name: c.Args().First()})
						if err != nil {
							return fmt.Errorf("Could not get ssh config for vm '%s': %v", c.Args().First(), err)
						}
						out, _ := json.Marshal(resp)
						fmt.Println(string(out))
						return nil
					},
				}}}, {
			Name:  "volume",
			Usage: "volume COMMAND",
			Subcommands: []cli.Command{
				{
					Name:  "list",
					Usage: "List available volumes",
					Action: func(c *cli.Context) error {
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						service := pb.NewVolumeServiceClient(conn)
						resp, err := service.List(ctx, &pb.Empty{})
						if err != nil {
							return fmt.Errorf("Could not get volume list: %v", err)
						}

						out, _ := json.Marshal(resp.GetVolumes())
						fmt.Println(string(out))

						return nil
					},
				}, {
					Name:      "inspect",
					Usage:     "Inspect volume",
					ArgsUsage: "<Volume_name|Volume_ID>",
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Missing mandatory argument <Volume_name|Volume_ID>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("Volume name or ID required")
						}
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						service := pb.NewVolumeServiceClient(conn)
						volume, err := service.Inspect(ctx, &pb.Reference{Name: c.Args().First()})
						if err != nil {
							return fmt.Errorf("Could not get volume '%s': %v", c.Args().First(), err)
						}

						out, _ := json.Marshal(volume)
						fmt.Println(string(out))

						return nil
					},
				}, {
					Name:      "delete",
					Usage:     "Delete volume",
					ArgsUsage: "<Volume_name|Volume_ID>",
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Missing mandatory argument <Volume_name|Volume_ID>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("Volume name or ID required")
						}
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						service := pb.NewVolumeServiceClient(conn)
						_, err := service.Delete(ctx, &pb.Reference{Name: c.Args().First()})
						if err != nil {
							return fmt.Errorf("Could not get volume '%s': %v", c.Args().First(), err)
						}
						fmt.Println(fmt.Sprintf("Volume '%s' deleted", c.Args().First()))

						return nil
					},
				}, {
					Name:      "create",
					Usage:     "Create a volume",
					ArgsUsage: "<Volume_name>",
					Flags: []cli.Flag{
						cli.IntFlag{
							Name:  "size",
							Value: 10,
							Usage: "Size of the volume (in Go)",
						},
						cli.StringFlag{
							Name:  "speed",
							Value: "HDD",
							// Improvement: get allowed values from brokerd.pb.go
							Usage: "Allowed values: SSD, HDD, COLD",
						},
					},
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Missing mandatory argument <Volume_name>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("Volume name required")
						}
						speed := c.String("speed")
						if _, ok := pb.VolumeSpeed_value[speed]; !ok {
							msg := fmt.Sprintf("Invalid volume speed '%s'", speed)
							fmt.Println(msg)
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf(msg)
						}

						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						service := pb.NewVolumeServiceClient(conn)
						volume, err := service.Create(ctx, &pb.VolumeDefinition{
							Name:  c.Args().First(),
							Size:  int32(c.Int("size")),
							Speed: pb.VolumeSpeed(pb.VolumeSpeed_value[speed]),
						})
						if err != nil {
							return fmt.Errorf("Could not create volume '%s': %v", c.Args().First(), err)
						}
						out, _ := json.Marshal(volume)
						fmt.Println(string(out))

						return nil
					},
				}, {
					Name:      "attach",
					Usage:     "Attach a volume to a VM",
					ArgsUsage: "<Volume_name|Volume_ID>, <VM_name|VM_ID>",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "path",
							Value: "/shared/",
							Usage: "Mount point of the volume",
						},
						cli.StringFlag{
							Name:  "format",
							Value: "ext4",
							Usage: "Filesystem format",
						},
					},
					Action: func(c *cli.Context) error {
						if c.NArg() != 2 {
							fmt.Println("Missing mandatory argument <Volume_name> and/or <VM_name>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("Volume and VM name required")
						}

						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						service := pb.NewVolumeServiceClient(conn)
						_, err := service.Attach(ctx, &pb.VolumeAttachment{
							Format:    c.String("format"),
							MountPath: c.String("path"),
							VM:        &pb.Reference{Name: c.Args().Get(1)},
							Volume:    &pb.Reference{Name: c.Args().Get(0)},
						})
						if err != nil {
							return fmt.Errorf("Could not attach volume '%s' to VM '%s': %v", c.Args().Get(0), c.Args().Get(1), err)
						}
						fmt.Println(fmt.Sprintf("Volume '%s' attached to vm '%s'", c.Args().Get(0), c.Args().Get(1)))

						return nil
					},
				}, {
					Name:      "detach",
					Usage:     "Detach a volume from a VM",
					ArgsUsage: "<Volume_name|Volume_ID> <VM_name|VM_ID>",
					Action: func(c *cli.Context) error {
						if c.NArg() != 2 {
							fmt.Println("Missing mandatory argument <Volume_name> and/or <VM_name>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("Volume and VM name required")
						}

						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						service := pb.NewVolumeServiceClient(conn)

						_, err := service.Detach(ctx, &pb.VolumeDetachment{
							Volume: &pb.Reference{Name: c.Args().Get(0)},
							VM:     &pb.Reference{Name: c.Args().Get(1)}})

						if err != nil {
							return fmt.Errorf("Could not detach volume '%s' from VM '%s': %v", c.Args().Get(0), c.Args().Get(1), err)
						}
						fmt.Println(fmt.Sprintf("Volume '%s' detached from VM '%s'", c.Args().Get(0), c.Args().Get(1)))

						return nil
					},
				}}}, {
			Name:  "ssh",
			Usage: "shh COMMAND",
			Subcommands: []cli.Command{
				{
					Name:      "run",
					Usage:     "Run a command on the VM",
					ArgsUsage: "<VM_name|VM_ID>",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "c",
							Usage: "Command to execute",
						},
					},
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Missing mandatory argument <VM_name>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("VM name required")
						}

						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxDefault)
						defer cancel()
						service := pb.NewSshServiceClient(conn)

						resp, err := service.Run(ctx, &pb.SshCommand{
							VM:      &pb.Reference{Name: c.Args().Get(0)},
							Command: c.String("c"),
						})

						// TODO output result to stdout
						if err != nil {
							return fmt.Errorf("Could not execute ssh command: %v", err)
						}
						fmt.Print(fmt.Sprintf(resp.GetOutput()))
						fmt.Fprint(os.Stderr, fmt.Sprintf(resp.GetErr()))
						// fmt.Println(fmt.Sprintf(string(resp.GetStatus())))

						return nil
					},
				}, {
					Name:      "copy",
					Usage:     "Copy a local file/directory to a VM or copy from VM to local",
					ArgsUsage: "from to  Ex: /my/local/file.txt vm1:/remote/path/",
					Action: func(c *cli.Context) error {
						if c.NArg() != 2 {
							fmt.Println("2 arguments (from and to) are required")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("2 arguments (from and to) are required")
						}

						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxVM)
						defer cancel()
						service := pb.NewSshServiceClient(conn)

						_, err := service.Copy(ctx, &pb.SshCopyCommand{
							Source:      c.Args().Get(0),
							Destination: c.Args().Get(1),
						})
						if err != nil {
							return fmt.Errorf("Could not copy %s to %s: %v", c.Args().Get(0), c.Args().Get(1), err)
						}
						fmt.Println(fmt.Sprintf("Copy of '%s' to '%s' done", c.Args().Get(0), c.Args().Get(1)))

						return nil
					},
				}, {
					Name:      "connect",
					Usage:     "Connect to the VM with interactive shell",
					ArgsUsage: "<VM_name|VM_ID>",
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Missing mandatory argument <VM_name>")
							cli.ShowSubcommandHelp(c)
							return fmt.Errorf("VM name required")
						}
						conn := getConnection()
						defer conn.Close()
						ctx, cancel := getContext(timeoutCtxVM)
						defer cancel()
						service := pb.NewVMServiceClient(conn)

						sshConfig, err := service.Ssh(ctx, &pb.Reference{
							Name: c.Args().Get(0),
						})
						if err != nil {
							return fmt.Errorf("Could not connect to %s: %v", c.Args().Get(0), err)
						}

						sshCfg := conv.ToAPISshConfig(sshConfig)

						return sshCfg.Enter()
					},
				}}},
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}
