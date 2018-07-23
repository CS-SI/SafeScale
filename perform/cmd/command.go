/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"fmt"

	"github.com/CS-SI/SafeScale/perform/cluster"

	"github.com/urfave/cli"
)

var (
	clusterName string
)

// CommandCmd command
var CommandCmd = cli.Command{
	Name:    "command",
	Aliases: []string{"cmd"},
	Usage:   "command COMMAND",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "cluster, c",
			Usage: "Name of the cluster",
		},
	},
	Action: func(c *cli.Context) error {
		clusterName := c.String("cluster")
		if clusterName == "" {
			fmt.Println("Missing mandatory options --cluster,-c <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return fmt.Errorf("failed to get cluster '%s' information: %s", clusterName, err.Error())
		}
		if instance == nil {
			return fmt.Errorf("cluster '%s' not found", clusterName)
		}
		fmt.Println("not yet implemented")
		return nil
	},
	Subcommands: []cli.Command{
		commandDcos,
		commandKubectl,
		commandMarathon,
	},
}

var commandDcos = cli.Command{
	Name:  "dcos",
	Usage: "Runs a dcos cli command",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "cluster, c",
			Usage: "Name of the cluster",
		},
	},
	Action: func(c *cli.Context) error {
		clusterName := c.String("cluster")
		if clusterName == "" {
			fmt.Println("Missing mandatory options --cluster,-c <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return fmt.Errorf("failed to get cluster '%s' information: %s", clusterName, err.Error())
		}
		if instance == nil {
			return fmt.Errorf("cluster '%s' not found", clusterName)
		}
		fmt.Println("not yet implemented")
		return nil
	},
}

var commandKubectl = cli.Command{
	Name:  "kubectl",
	Usage: "Runs a kubectl command",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "cluster, c",
			Usage: "Name of the cluster",
		},
	},
	Action: func(c *cli.Context) error {
		clusterName := c.String("cluster")
		if clusterName == "" {
			fmt.Println("Missing mandatory options --cluster <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return fmt.Errorf("failed to get cluster '%s' information: %s", clusterName, err.Error())
		}
		if instance == nil {
			return fmt.Errorf("cluster '%s' not found", clusterName)
		}
		fmt.Println("not yet implemented")
		return nil
	},
}

var commandMarathon = cli.Command{
	Name:  "marathon",
	Usage: "Run a marathon command",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "cluster, n",
			Usage: "Name of the cluster",
		},
	},
	Action: func(c *cli.Context) error {
		clusterName := c.String("cluster")
		if clusterName == "" {
			fmt.Println("Missing mandatory options --cluster <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return fmt.Errorf("failed to get cluster '%s' information: %s", clusterName, err.Error())
		}
		if instance == nil {
			return fmt.Errorf("cluster '%s' not found", clusterName)
		}
		fmt.Println("not yet implemented")
		return nil
	},
}
