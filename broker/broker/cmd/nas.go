package cmd

import (
	"encoding/json"
	"fmt"

	pb "github.com/SafeScale/broker"
	utils "github.com/SafeScale/broker/utils"
	"github.com/SafeScale/providers/api"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/urfave/cli"
)

//NasCmd ssh command
var NasCmd = cli.Command{
	Name:  "nas",
	Usage: "nas COMMAND",
	Subcommands: []cli.Command{
		nasCreate,
		nasDelete,
		// nasMount,
		// nasUmount,
		nasList,
		// nasInspect,
	},
}

var nasCreate = cli.Command{
	Name:      "create",
	Usage:     "Create a nfs server on a VM and expose a directory",
	ArgsUsage: "<Nas_name> <VM_name|VM_ID>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "path",
			Value: api.DefaultNasExposedPath,
			Usage: "Path to be exported",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("Missing mandatory argument <Nas_name> and/or <VM_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Nas and VM name required")
		}

		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewNasServiceClient(conn)

		_, err := service.Create(ctx, &pb.NasDefinition{
			Nas:  &pb.NasName{Name: c.Args().Get(0)},
			VM:   &pb.Reference{Name: c.Args().Get(1)},
			Path: c.String("path"),
		})

		// TODO output result to stdout
		if err != nil {
			return fmt.Errorf("Could not create nas: %v", err)
		}

		return nil
	},
}

var nasDelete = cli.Command{
	Name:      "delete",
	Usage:     "Delete a nfs server on a VM and expose a directory",
	ArgsUsage: "<Nas_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Nas_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Nas name required")
		}

		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxVM)
		defer cancel()
		service := pb.NewNasServiceClient(conn)

		_, err := service.Delete(ctx, &pb.NasName{Name: c.Args().Get(0)})

		// TODO output result to stdout
		if err != nil {
			return fmt.Errorf("Could not delete nas: %v", err)
		}

		return nil
	},
}

var nasList = cli.Command{
	Name:  "list",
	Usage: "List all created nas",
	Action: func(c *cli.Context) error {
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxVM)
		defer cancel()
		service := pb.NewNasServiceClient(conn)

		nass, err := service.List(ctx, &google_protobuf.Empty{})

		if err != nil {
			return fmt.Errorf("Could not get nas list: %v", err)
		}
		out, _ := json.Marshal(nass.GetNasList())
		fmt.Println(string(out))

		return nil
	},
}
