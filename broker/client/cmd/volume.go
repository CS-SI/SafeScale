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
	"encoding/json"
	"fmt"

	pb "github.com/CS-SI/SafeScale/broker"
	utils "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/utils/brokeruse"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/urfave/cli"
)

//VolumeCmd volume command
var VolumeCmd = cli.Command{
	Name:  "volume",
	Usage: "volume COMMAND",
	Subcommands: []cli.Command{
		volumeList,
		volumeInspect,
		volumeDelete,
		volumeCreate,
		volumeAttach,
		volumeDetach,
	},
}

var volumeList = cli.Command{
	Name:  "list",
	Usage: "List available volumes",
	Action: func(c *cli.Context) error {
		conn := brokeruse.GetConnection()
		defer conn.Close()
		ctx, cancel := brokeruse.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewVolumeServiceClient(conn)
		resp, err := service.List(ctx, &google_protobuf.Empty{})
		if err != nil {
			return fmt.Errorf("Could not get volume list: %v", err)
		}

		out, _ := json.Marshal(resp.GetVolumes())
		fmt.Println(string(out))

		return nil
	},
}

var volumeInspect = cli.Command{
	Name:      "inspect",
	Usage:     "Inspect volume",
	ArgsUsage: "<Volume_name|Volume_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Volume_name|Volume_ID>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Volume name or ID required")
		}
		conn := brokeruse.GetConnection()
		defer conn.Close()
		ctx, cancel := brokeruse.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewVolumeServiceClient(conn)
		volume, err := service.Inspect(ctx, &pb.Reference{Name: c.Args().First()})
		if err != nil {
			return fmt.Errorf("Could not get volume '%s': %v", c.Args().First(), err)
		}

		out, _ := json.Marshal(volume)
		fmt.Println(string(out))

		return nil
	},
}

var volumeDelete = cli.Command{
	Name:      "delete",
	Usage:     "Delete volume",
	ArgsUsage: "<Volume_name|Volume_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Volume_name|Volume_ID>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Volume name or ID required")
		}
		conn := brokeruse.GetConnection()
		defer conn.Close()
		ctx, cancel := brokeruse.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewVolumeServiceClient(conn)
		_, err := service.Delete(ctx, &pb.Reference{Name: c.Args().First()})
		if err != nil {
			return fmt.Errorf("Could not delete volume '%s': %v", c.Args().First(), err)
		}
		fmt.Println(fmt.Sprintf("Volume '%s' deleted", c.Args().First()))

		return nil
	},
}

var volumeCreate = cli.Command{
	Name:      "create",
	Usage:     "Create a volume",
	ArgsUsage: "<Volume_name>",
	Flags: []cli.Flag{
		cli.IntFlag{
			Name:  "size",
			Value: 10,
			Usage: "Size of the volume (in Go)",
		},
		cli.StringFlag{
			Name:  "speed",
			Value: "HDD",
			// Improvement: get allowed values from brokerd.pb.go
			Usage: "Allowed values: SSD, HDD, COLD",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Volume_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Volume name required")
		}
		speed := c.String("speed")
		if _, ok := pb.VolumeSpeed_value[speed]; !ok {
			msg := fmt.Sprintf("Invalid volume speed '%s'", speed)
			fmt.Println(msg)
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf(msg)
		}

		conn := brokeruse.GetConnection()
		defer conn.Close()
		ctx, cancel := brokeruse.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewVolumeServiceClient(conn)
		volume, err := service.Create(ctx, &pb.VolumeDefinition{
			Name:  c.Args().First(),
			Size:  int32(c.Int("size")),
			Speed: pb.VolumeSpeed(pb.VolumeSpeed_value[speed]),
		})
		if err != nil {
			return fmt.Errorf("Could not create volume '%s': %v", c.Args().First(), err)
		}
		out, _ := json.Marshal(volume)
		fmt.Println(string(out))

		return nil
	},
}

var volumeAttach = cli.Command{
	Name:      "attach",
	Usage:     "Attach a volume to a VM",
	ArgsUsage: "<Volume_name|Volume_ID>, <VM_name|VM_ID>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "path",
			Value: api.DefaultVolumeMountPoint,
			Usage: "Mount point of the volume",
		},
		cli.StringFlag{
			Name:  "format",
			Value: "ext4",
			Usage: "Filesystem format",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("Missing mandatory argument <Volume_name> and/or <VM_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Volume and VM name required")
		}

		conn := brokeruse.GetConnection()
		defer conn.Close()
		ctx, cancel := brokeruse.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewVolumeServiceClient(conn)
		_, err := service.Attach(ctx, &pb.VolumeAttachment{
			Format:    c.String("format"),
			MountPath: c.String("path"),
			VM:        &pb.Reference{Name: c.Args().Get(1)},
			Volume:    &pb.Reference{Name: c.Args().Get(0)},
		})
		if err != nil {
			return fmt.Errorf("Could not attach volume '%s' to VM '%s': %v", c.Args().Get(0), c.Args().Get(1), err)
		}
		fmt.Println(fmt.Sprintf("Volume '%s' attached to vm '%s'", c.Args().Get(0), c.Args().Get(1)))

		return nil
	},
}

var volumeDetach = cli.Command{
	Name:      "detach",
	Usage:     "Detach a volume from a VM",
	ArgsUsage: "<Volume_name|Volume_ID> <VM_name|VM_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("Missing mandatory argument <Volume_name> and/or <VM_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Volume and VM name required")
		}

		conn := brokeruse.GetConnection()
		defer conn.Close()
		ctx, cancel := brokeruse.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewVolumeServiceClient(conn)

		_, err := service.Detach(ctx, &pb.VolumeDetachment{
			Volume: &pb.Reference{Name: c.Args().Get(0)},
			VM:     &pb.Reference{Name: c.Args().Get(1)}})

		if err != nil {
			return fmt.Errorf("Could not detach volume '%s' from VM '%s': %v", c.Args().Get(0), c.Args().Get(1), err)
		}
		fmt.Println(fmt.Sprintf("Volume '%s' detached from VM '%s'", c.Args().Get(0), c.Args().Get(1)))

		return nil
	},
}
