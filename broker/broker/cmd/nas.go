package cmd

import (
	"fmt"

	pb "github.com/SafeScale/broker"
	utils "github.com/SafeScale/broker/utils"
	"github.com/SafeScale/providers/api"
	"github.com/urfave/cli"
)

//NasCmd ssh command
var NasCmd = cli.Command{
	Name:  "nas",
	Usage: "nas COMMAND",
	Subcommands: []cli.Command{
		nasCreate,
		// nasDelete,
		// nasMount,
		// nasUmount,
		// nasList,
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
