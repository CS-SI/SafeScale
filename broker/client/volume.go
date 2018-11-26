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

package client

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	clitools "github.com/CS-SI/SafeScale/utils"
)

// volume is the part of broker client handing volumes
type volume struct {
	// session is not used currently
	session *Session
}

// List ...
func (v *volume) List(all bool, timeout time.Duration) (*pb.VolumeList, error) {
	v.session.Connect()
	defer v.session.Disconnect()
	service := pb.NewVolumeServiceClient(v.session.connection)
	ctx := context.Background()

	return service.List(ctx, &pb.VolumeListRequest{All: all})

}

// Inspect ...
func (v *volume) Inspect(name string, timeout time.Duration) (*pb.VolumeInfo, error) {
	v.session.Connect()
	defer v.session.Disconnect()
	service := pb.NewVolumeServiceClient(v.session.connection)
	ctx := context.Background()

	return service.Inspect(ctx, &pb.Reference{Name: name})

}

// Delete ...
func (v *volume) Delete(names []string, timeout time.Duration) error {
	v.session.Connect()
	defer v.session.Disconnect()
	service := pb.NewVolumeServiceClient(v.session.connection)
	ctx := context.Background()

	var (
		wg   sync.WaitGroup
		errs int
	)

	volumeDeleter := func(aname string) {
		defer wg.Done()
		_, err := service.Delete(ctx, &pb.Reference{Name: aname})

		if err != nil {
			fmt.Fprintln(os.Stderr, DecorateError(err, "deletion of volume", true).Error())
			errs++
		} else {
			fmt.Printf("Volume '%s' deleted\n", aname)
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go volumeDeleter(target)
	}
	wg.Wait()

	if errs > 0 {
		return clitools.ExitOnRPC("")
	}
	return nil

}

// Create ...
func (v *volume) Create(def pb.VolumeDefinition, timeout time.Duration) (*pb.Volume, error) {
	v.session.Connect()
	defer v.session.Disconnect()
	service := pb.NewVolumeServiceClient(v.session.connection)
	ctx := context.Background()

	return service.Create(ctx, &def)

}

// Attach ...
func (v *volume) Attach(def pb.VolumeAttachment, timeout time.Duration) error {
	v.session.Connect()
	defer v.session.Disconnect()
	service := pb.NewVolumeServiceClient(v.session.connection)
	ctx := context.Background()

	_, err := service.Attach(ctx, &def)
	return err

}

// Detach ...
func (v *volume) Detach(volumeName string, hostName string, timeout time.Duration) error {
	v.session.Connect()
	defer v.session.Disconnect()
	service := pb.NewVolumeServiceClient(v.session.connection)
	ctx := context.Background()

	_, err := service.Detach(ctx, &pb.VolumeDetachment{
		Volume: &pb.Reference{Name: volumeName},
		Host:   &pb.Reference{Name: hostName},
	})
	return err
}
