/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package commands

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Complexity"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/ExitCode"
)

var (
	performCommandName = "perform"

	// PerformCommand command
	PerformCommand = cli.Command{
		Name:      "perform",
		Usage:     "create and manage platform with pre-defined list of software",
		ArgsUsage: "COMMAND",
		Subcommands: []cli.Command{
			performCreateCommand,
		},
	}
)

// performCreateCmd handles 'perform create <platform_name>'
var performCreateCommand = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create a platform with pre-defined list of software",
	ArgsUsage: "CLUSTERNAME",

	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "complexity, C",
			Value: "Normal",
			Usage: "Defines the sizing of the platform: Normal, Large",
		},
		cli.StringFlag{
			Name:  "Kind, K",
			Usage: "This parameter defines the additional software to install on platform: K8S-Monitored",
		},
	},

	Action: func(c *cli.Context) (err error) {
		log.Tracef("SafeScale command: {%s}, {%s} with args {%s}", performCommandName, c.Command.Name, c.Args())
		err = extractClusterArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		complexityStr := c.String("complexity")
		complexity, err := Complexity.Parse(complexityStr)
		if err != nil {
			msg := fmt.Sprintf("Invalid option --complexity|-C: %s\n", err.Error())
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(msg))
		}
		if complexity == Complexity.Small {
			msg := fmt.Sprintf("Invalid option --complexity|-C: Small is not permitted with perform")
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(msg))
		}
		kindStr := c.String("kind")

		switch strings.ToLower(kindStr) {
		case "monitored-k8s":
			return createMonitoredK8S(complexityStr)
		}

		msg := fmt.Sprintf("Invalid option --kind|-K: unknown kind '%s'\n", kindStr)
		return clitools.FailureResponse(clitools.ExitOnInvalidOption(msg))
	},
}

// create_monitored_k8s creates a K8S platform and installs monitoring software
func createMonitoredK8S(complexity string) error {
	// Create cluster with deploy
	cmdStr := fmt.Sprintf("safescale platform create %s -F K8S -C %s -N 192.168.0.0/16", clusterName, complexity)
	err := runCommand(cmdStr)
	if err != nil {
		return err
	}

	// // Installs feature Spark
	// cmdStr = fmt.Sprintf("safescale platform add-feature %s sparkmaster", clusterName)
	// err = runCommand(cmdStr)
	// if err != nil {
	// 	return err
	// }

	// Done
	return nil
}

func runCommand(cmdStr string) error {
	cmd := exec.Command("bash", "-c", cmdStr)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	stdoutScanner := bufio.NewScanner(stdout)
	stderrScanner := bufio.NewScanner(stderr)
	go func() {
		for stdoutScanner.Scan() {
			fmt.Println(stdoutScanner.Text())
		}
	}()
	go func() {
		for stderrScanner.Scan() {
			_, _ = fmt.Fprintln(os.Stderr, stderrScanner.Text())
		}
	}()

	err := cmd.Start()
	if err != nil {
		return cli.NewExitError(err.Error(), int(ExitCode.Run))
	}

	err = cmd.Wait()
	if err != nil {
		return cli.NewExitError(err.Error(), int(ExitCode.Run))
	}
	return nil
}
