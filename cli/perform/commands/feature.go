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
	//log "github.com/sirupsen/logrus"

	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/cli/perform/enums/ExitCode"
)

// ClusterProbeFeatureCommand ...
var ClusterProbeFeatureCommand = cli.Command{
	Name:        "probe-feature",
	Aliases:     []string{"check-feature"},
	Usage:       "probe-feature CLUSTERNAME FEATURENAME",
	Description: "Determines if feature is installed on cluster.",
	Category:    "Features",

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		err = extractFeatureArgument(c)
		if err != nil {
			return err
		}
		return cli.NewExitError("Not yet implemented", int(ExitCode.NotImplemented))
	},
}

// ClusterAddFeatureCommand ...
var ClusterAddFeatureCommand = cli.Command{
	Name:        "add-feature",
	Usage:       "add-feature CLUSTERNAME FEATURENAME",
	Description: "Adds a feature on the cluster",
	Category:    "Features",

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "skip-proxy",
		},
		cli.StringSliceFlag{
			Name: "param, p",
		},
	},

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		err = extractFeatureArgument(c)
		if err != nil {
			return err
		}
		return cli.NewExitError("Not yet implemented", int(ExitCode.NotImplemented))
	},
}

// ClusterDeleteFeatureCommand ...
var ClusterDeleteFeatureCommand = cli.Command{
	Name:     "delete-feature",
	Aliases:  []string{"rm-feature", "uninstall-feature", "remove-feature"},
	Usage:    "Deletes a feature from the cluster",
	Category: "Features",

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		err = extractFeatureArgument(c)
		if err != nil {
			return err
		}
		return cli.NewExitError("Not yet implemented", int(ExitCode.NotImplemented))
	},
}

// ClusterStateFeatureCommand ...
var ClusterStateFeatureCommand = cli.Command{
	Name:     "state-feature",
	Aliases:  []string{"status-feature"},
	Usage:    "Determines the state of the feature (if the feature behaves like service)",
	Category: "Features",

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		err = extractFeatureArgument(c)
		if err != nil {
			return err
		}
		return cli.NewExitError("Not yet implemented", int(ExitCode.NotImplemented))
	},
}

// ClusterStartFeatureCommand ...
var ClusterStartFeatureCommand = cli.Command{
	Name:     "start-feature",
	Usage:    "Starts a stopped feature (if the feature behaves like service)",
	Category: "Features",

	Action: func(c *cli.Context) error {
		err := extractFeatureArgument(c)
		if err != nil {
			return err
		}
		return cli.NewExitError("Not yet implemented", int(ExitCode.NotImplemented))
	},
}

// ClusterStopFeatureCommand ...
var ClusterStopFeatureCommand = cli.Command{
	Name:     "stop-feature",
	Usage:    "Stops a started feature (if the feature behaves like a service)",
	Category: "Features",

	Action: func(c *cli.Context) error {
		err := extractFeatureArgument(c)
		if err != nil {
			return err
		}
		return cli.NewExitError("Not yet implemented", int(ExitCode.NotImplemented))
	},
}

// ClusterEnableFeatureCommand ...
var ClusterEnableFeatureCommand = cli.Command{
	Name:     "enable-feature",
	Usage:    "Enables a feature (if the feature behaves like a service)",
	Category: "Features",

	Action: func(c *cli.Context) error {
		err := extractFeatureArgument(c)
		if err != nil {
			return err
		}
		return cli.NewExitError("Not yet implemented", int(ExitCode.NotImplemented))
	},
}

// ClusterDisableFeatureCommand ...
var ClusterDisableFeatureCommand = cli.Command{
	Name:        "disable-feature",
	Usage:       "disable-feature FEATURENAME",
	Description: "Disables a feature (if the feature behaves like a service)",
	Category:    "Features",

	Action: func(c *cli.Context) error {
		featureName := c.Args().Get(1)

		if featureName == "" {
			msg := "Invalid empty argument FEATURENAME"
			return cli.NewExitError(msg, int(ExitCode.InvalidArgument))
		}
		return cli.NewExitError("Not yet implemented", int(ExitCode.NotImplemented))
	},
}
