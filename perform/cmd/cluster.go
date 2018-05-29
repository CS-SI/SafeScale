package cmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/SafeScale/perform/cluster"
	clusterapi "github.com/SafeScale/perform/cluster/api"
	"github.com/SafeScale/perform/cluster/api/Complexity"
	"github.com/SafeScale/perform/cluster/api/Flavor"
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
	Usage: "List available Clusters on the current tenant",
	Action: func(c *cli.Context) error {
		list, err := cluster.List()
		if err != nil {
			return fmt.Errorf("Could not get cluster list: %v", err)
		}
		out, _ := json.Marshal(list)
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
		instance, err := cluster.Get(c.Args().First())
		if err != nil {
			return fmt.Errorf("Could not inspect cluster '%s': %v", c.Args().First(), err)
		}
		out, _ := json.Marshal(instance.GetDefinition())
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
			Value: "Normal",
			Usage: "Complexity of the cluster; can be DEV, NORMAL, VOLUME",
		},
		cli.StringFlag{
			Name:  "cidr",
			Value: "192.168.0.0/24",
			Usage: "CIDR of the network",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		clusterName := c.Args().First()
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return err
		}
		if instance != nil {
			return fmt.Errorf("cluster '%s' already exists.", clusterName)
		}
		log.Printf("Cluster '%s' not found, creating it (this will take a while)\n", clusterName)
		complexity, err := Complexity.FromString(c.String("complexity"))
		if err != nil {
			return err
		}
		instance, err = cluster.Create(clusterapi.Request{
			Name:       clusterName,
			Complexity: complexity,
			CIDR:       c.String("cidr"),
			Flavor:     Flavor.DCOS,
		})
		if err != nil {
			return fmt.Errorf("Failed to create cluster: %s", err.Error())
		}

		out, _ := json.Marshal(instance.GetDefinition())
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
		err := cluster.Delete(c.Args().First())
		if err != nil {
			return err
		}

		fmt.Printf("Cluster '%s' deleted.\n", c.Args().First())

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
		instance, err := cluster.Get(c.Args().First())
		if err != nil {
			return err
		}
		err = instance.Stop()
		if err != nil {
			return err
		}
		fmt.Printf("Cluster '%s' stopped.\n", c.Args().First())

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
		instance, err := cluster.Get(c.Args().First())
		if err != nil {
			return nil
		}
		err = instance.Start()
		if err != nil {
			return err
		}

		fmt.Printf("Cluster '%s' started.\n", c.Args().First())

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
		instance, err := cluster.Get(c.Args().First())
		if err != nil {
			return err
		}
		state, err := instance.GetState()
		if err != nil {
			return err
		}

		fmt.Printf("Cluster '%s' state : %s\n", c.Args().First(), state.String())

		return nil
	},
}
