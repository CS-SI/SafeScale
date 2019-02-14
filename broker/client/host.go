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
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	conv "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/system"
	cache "github.com/CS-SI/SafeScale/utils"
	clitools "github.com/CS-SI/SafeScale/utils"
)

var sshCfgCache = cache.NewMapCache()

// host is the broker client part handling hosts
type host struct {
	// session is not used currently
	session *Session
}

// List ...
func (h *host) List(all bool, timeout time.Duration) (*pb.HostList, error) {
	h.session.Connect()
	defer h.session.Disconnect()
	service := pb.NewHostServiceClient(h.session.connection)
	ctx := context.Background()

	return service.List(ctx, &pb.HostListRequest{All: all})
}

// Inspect ...
func (h *host) Inspect(name string, timeout time.Duration) (*pb.Host, error) {
	h.session.Connect()
	defer h.session.Disconnect()
	service := pb.NewHostServiceClient(h.session.connection)
	ctx := context.Background()

	return service.Inspect(ctx, &pb.Reference{Name: name})

}

// Get host status
func (h *host) Status(name string, timeout time.Duration) (*pb.HostStatus, error) {
	h.session.Connect()
	defer h.session.Disconnect()
	service := pb.NewHostServiceClient(h.session.connection)
	ctx := context.Background()

	return service.Status(ctx, &pb.Reference{Name: name})
}

// Reboots host
func (h *host) Reboot(name string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()
	service := pb.NewHostServiceClient(h.session.connection)
	ctx := context.Background()

	_, err := service.Reboot(ctx, &pb.Reference{Name: name})
	return err
}

// Start host
func (h *host) Start(name string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()
	service := pb.NewHostServiceClient(h.session.connection)
	ctx := context.Background()

	_, err := service.Start(ctx, &pb.Reference{Name: name})
	return err
}

func (h *host) Stop(name string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()
	service := pb.NewHostServiceClient(h.session.connection)
	ctx := context.Background()

	_, err := service.Stop(ctx, &pb.Reference{Name: name})
	return err
}

// Create ...
func (h *host) Create(def pb.HostDefinition, timeout time.Duration) (*pb.Host, error) {
	h.session.Connect()
	defer h.session.Disconnect()
	service := pb.NewHostServiceClient(h.session.connection)
	ctx := context.Background()

	return service.Create(ctx, &def)
}

// Delete deletes several hosts at the same time in goroutines
func (h *host) Delete(names []string, timeout time.Duration) error {
	h.session.Connect()
	defer h.session.Disconnect()
	service := pb.NewHostServiceClient(h.session.connection)
	ctx := context.Background()

	var (
		wg   sync.WaitGroup
		errs int32
	)

	hostDeleter := func(aname string) {
		defer wg.Done()
		_, err := service.Delete(ctx, &pb.Reference{Name: aname})
		if err != nil {
			fmt.Printf("%v\n", DecorateError(err, "deletion of host", true))
			atomic.AddInt32(&errs, 1)
		} else {
			fmt.Printf("Host '%s' deleted\n", aname)
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go hostDeleter(target)
	}
	wg.Wait()

	if errs > 0 {
		return clitools.ExitOnRPC("")
	}
	return nil
}

// SSHConfig ...
func (h *host) SSHConfig(name string) (*system.SSHConfig, error) {
	if anon, ok := sshCfgCache.Get(name); ok {
		return anon.(*system.SSHConfig), nil
	}

	h.session.Connect()
	defer h.session.Disconnect()
	service := pb.NewHostServiceClient(h.session.connection)
	ctx := context.Background()

	pbSSHCfg, err := service.SSH(ctx, &pb.Reference{Name: name})
	if err != nil {
		return nil, err
	}
	sshCfg := conv.ToSystemSshConfig(pbSSHCfg)
	if err == nil {
		nerr := sshCfgCache.Set(name, sshCfg)
		if nerr != nil {
			return sshCfg, nerr
		}
	}
	return sshCfg, err
}

func (h *host) Resize(def pb.HostDefinition, duration time.Duration) (*pb.Host, error) {
	h.session.Connect()
	defer h.session.Disconnect()
	service := pb.NewHostServiceClient(h.session.connection)
	ctx := context.Background()

	return service.Resize(ctx, &def)
}
