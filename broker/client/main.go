package main

import (
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"github.com/SafeScale/broker/client/cmd"
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

	app.Commands = append(app.Commands, cmd.NetworkCmd)
	sort.Sort(cli.CommandsByName(cmd.NetworkCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.TenantCmd)
	sort.Sort(cli.CommandsByName(cmd.TenantCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.VMCmd)
	sort.Sort(cli.CommandsByName(cmd.VMCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.VolumeCmd)
	sort.Sort(cli.CommandsByName(cmd.VolumeCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.SSHCmd)
	sort.Sort(cli.CommandsByName(cmd.SSHCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.ContainerCmd)
	sort.Sort(cli.CommandsByName(cmd.ContainerCmd.Subcommands))

	app.Commands = append(app.Commands, cmd.NasCmd)
	sort.Sort(cli.CommandsByName(cmd.NasCmd.Subcommands))

	sort.Sort(cli.CommandsByName(app.Commands))
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}
