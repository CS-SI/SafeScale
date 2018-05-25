package cmd

import (
	"encoding/json"
	"fmt"

	pb "github.com/SafeScale/broker"
	utils "github.com/SafeScale/broker/utils"
	"github.com/SafeScale/perform/cluster"
	"github.com/urfave/cli"
)

// ClusterCmd command
var ClusterCmd = cli.Command{
	Name:  "cluster",
	Usage: "cluster COMMAND",
	Subcommands: []cli.Command{
		clusterList,
		clusterCreate,
		clusterDelete,
		clusterInspect,
		clusterStop,
		clusterStart,
		clusterState,
	},
}

var clusterList = cli.Command{
	Name:  "list",
	Usage: "List available Clusters on the selected tenant",
	Action: func(c *cli.Context) error {
		tenant, err := getCurrentTenant()
		if err != nil {
			return err
		}
		cf := cluster.NewFactory()
		manager, err := cf.GetManager(tenant)
		clusters, err := manager.ListClusters()
		if err != nil {
			return fmt.Errorf("Could not get cluster list: %v", err)
		}
		out, _ := json.Marshal(clusters)
		fmt.Println(string(out))

		return nil
	},
}

var clusterInspect = cli.Command{
	Name:      "inspect",
	Usage:     "inspect Cluster",
	ArgsUsage: "<cluster name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		tenant, err := getCurrentTenant()
		if err != nil {
			return err
		}
		cf := cluster.NewFactory()
		manager, err := cf.GetManager(tenant)
		if err != nil {
			return fmt.Errorf("Could not create cluster manager: %v", err)
		}
		cluster, err := manager.GetCluster(c.Args().First())
		if err != nil {
			return fmt.Errorf("Could not inspect cluster '%s': %v", c.Args().First(), err)
		}
		out, _ := json.Marshal(cluster.GetDefinition())
		fmt.Println(string(out))

		return nil
	},
}

var clusterCreate = cli.Command{
	Name:      "create",
	Usage:     "create a new cluster",
	ArgsUsage: "<cluster name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "complexity",
			Usage: "Complexity of the cluster; can be DEV, NORMAL, VOLUME",
		},
		cli.StringFlag{
			Name:  "cidr",
			Usage: "CIDR of the underlying network",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("CLuster name required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxVM)
		defer cancel()
		service := pb.NewVMServiceClient(conn)
		resp, err := service.Create(ctx, &pb.VMDefinition{
			Name:      c.Args().First(),
			CPUNumber: int32(c.Int("cpu")),
			Disk:      int32(c.Float64("disk")),
			ImageID:   c.String("os"),
			Network:   c.String("net"),
			Public:    !c.Bool("private"),
			RAM:       float32(c.Float64("ram")),
		})
		if err != nil {
			return fmt.Errorf("Could not create vm '%s': %v", c.Args().First(), err)
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))

		return nil
	},
}

var clusterDelete = cli.Command{
	Name:      "delete",
	Usage:     "Delete cluster",
	ArgsUsage: "<cluster name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewVMServiceClient(conn)
		_, err := service.Delete(ctx, &pb.Reference{Name: c.Args().First()})
		if err != nil {
			return fmt.Errorf("Could not delete vm '%s': %v", c.Args().First(), err)
		}
		fmt.Printf("VM '%s' deleted\n", c.Args().First())
		return nil
	},
}

var clusterStop = cli.Command{
	Name:      "stop",
	Usage:     "Stop the cluster",
	ArgsUsage: "<cluster name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewVMServiceClient(conn)
		resp, err := service.SSH(ctx, &pb.Reference{Name: c.Args().First()})
		if err != nil {
			return fmt.Errorf("Could not get ssh config for vm '%s': %v", c.Args().First(), err)
		}
		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return nil
	},
}

var clusterStart = cli.Command{
	Name:      "start",
	Usage:     "Start the cluster",
	ArgsUsage: "<cluster name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewVMServiceClient(conn)
		resp, err := service.SSH(ctx, &pb.Reference{Name: c.Args().First()})
		if err != nil {
			return fmt.Errorf("Could not get ssh config for vm '%s': %v", c.Args().First(), err)
		}
		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return nil
	},
}

var clusterState = cli.Command{
	Name:      "state",
	Usage:     "Get cluster state",
	ArgsUsage: "<cluster name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewVMServiceClient(conn)
		resp, err := service.SSH(ctx, &pb.Reference{Name: c.Args().First()})
		if err != nil {
			return fmt.Errorf("Could not get ssh config for vm '%s': %v", c.Args().First(), err)
		}
		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return nil
	},
}
