package cmd

import (
	"encoding/json"
	"fmt"

	pb "github.com/SafeScale/broker"
	utils "github.com/SafeScale/broker/utils"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/urfave/cli"
)

//ContainerCmd container command
var ContainerCmd = cli.Command{
	Name:  "container",
	Usage: "container COMMAND",
	Subcommands: []cli.Command{
		containerList,
		containerCreate,
		containerDelete,
		containerInspect,
	},
}

var containerList = cli.Command{
	Name:  "list",
	Usage: "List containers",
	Action: func(c *cli.Context) error {
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewContainerServiceClient(conn)

		resp, err := service.List(ctx, &google_protobuf.Empty{})
		if err != nil {
			return fmt.Errorf("Could not list containers: %v", err)
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return nil
	},
}

var containerCreate = cli.Command{
	Name:      "create",
	Usage:     "Creates a container",
	ArgsUsage: "<Container_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Container_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Container name required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewContainerServiceClient(conn)

		_, err := service.Create(ctx, &pb.Container{Name: c.Args().Get(0)})
		if err != nil {
			return fmt.Errorf("Could not create container '%s': %v", c.Args().Get(0), err)
		}

		return nil
	},
}

var containerDelete = cli.Command{
	Name:      "delete",
	Usage:     "Delete a container",
	ArgsUsage: "<Container_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Container_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Container name required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewContainerServiceClient(conn)

		_, err := service.Delete(ctx, &pb.Container{Name: c.Args().Get(0)})
		if err != nil {
			return fmt.Errorf("Could not delete container '%s': %v", c.Args().Get(0), err)
		}

		return nil
	},
}

var containerInspect = cli.Command{
	Name:      "inspect",
	Usage:     "Inspect a container",
	ArgsUsage: "<Container_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Container_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Container name required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewContainerServiceClient(conn)

		resp, err := service.Inspect(ctx, &pb.Container{Name: c.Args().Get(0)})
		if err != nil {
			return fmt.Errorf("Could not delete container '%s': %v", c.Args().Get(0), err)
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return nil
	},
}
