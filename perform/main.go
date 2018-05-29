package main

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/CS-SI/SafeScale/perform/cmd"

	cli "github.com/urfave/cli"
)

const (
	address           = "localhost:50051"
	timeoutCtxDefault = 10 * time.Second
	timeoutCtxVM      = 2 * time.Minute
)

func main() {
	app := cli.NewApp()
	app.Name = "perform"
	app.Usage = "perform COMMAND"
	app.Version = "0.0.1"
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "CS-SI",
			Email: "safescale@c-s.fr",
		},
	}
	app.EnableBashCompletion = true

	app.Commands = append(app.Commands, cmd.ClusterCmd)
	sort.Sort(cli.CommandsByName(cmd.ClusterCmd.Subcommands))

	//app.Commands = append(app.Commands, cmd.TenantCmd)
	//sort.Sort(cli.CommandsByName(cmd.TenantCmd.Subcommands))

	sort.Sort(cli.CommandsByName(app.Commands))
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}
