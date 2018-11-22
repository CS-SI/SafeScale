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
	"fmt"
	"google.golang.org/grpc/status"
	"strings"
	"sync"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/utils"
	conv "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/system"
	cache "github.com/CS-SI/SafeScale/utils"
)

var sshCfgCache = cache.NewMapCache()

// host is the broker client part handling hosts
type host struct {
	// session is not used currently
	session *Session
}

// List ...
func (h *host) List(all bool, timeout time.Duration) (*pb.HostList, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxHost {
		timeout = utils.TimeoutCtxHost
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewHostServiceClient(conn)
	return service.List(ctx, &pb.HostListRequest{All: all})
}

// Inspect ...
func (h *host) Inspect(name string, timeout time.Duration) (*pb.Host, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewHostServiceClient(conn)
	return service.Inspect(ctx, &pb.Reference{Name: name})
}

// Get host status
func (h *host) Status(name string, timeout time.Duration) (*pb.HostStatus, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewHostServiceClient(conn)

	theHost, theErr := service.Status(ctx, &pb.Reference{Name: name})

	return theHost, theErr
}

// Reboots host
func (h *host) Reboot(name string, timeout time.Duration) (interface{}, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewHostServiceClient(conn)
	return service.Reboot(ctx, &pb.Reference{Name: name})
}

// Start host
func (h *host) Start(name string, timeout time.Duration) (interface{}, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewHostServiceClient(conn)
	return service.Start(ctx, &pb.Reference{Name: name})
}

func (h *host) Stop(name string, timeout time.Duration) (interface{}, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxDefault {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewHostServiceClient(conn)
	return service.Stop(ctx, &pb.Reference{Name: name})
}

// Create ...
func (h *host) Create(def pb.HostDefinition, timeout time.Duration) (*pb.Host, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxHost {
		timeout = utils.TimeoutCtxHost
	}
	ctx, cancel := utils.GetContext(timeout)
	defer cancel()
	service := pb.NewHostServiceClient(conn)
	return service.Create(ctx, &def)
}

// Delete deletes several hosts at the same time in goroutines
func (h *host) Delete(names []string, timeout time.Duration) error {
	conn := utils.GetConnection()
	defer conn.Close()
	if timeout < utils.TimeoutCtxHost {
		timeout = utils.TimeoutCtxHost
	}

	timeout = timeout + (30 * time.Second * time.Duration(len(names)))

	var wg sync.WaitGroup
	problems := false
	deleteErrors := make(chan error, len(names))

	hostDeleter := func(aname string) {
		defer wg.Done()
		ctx, cancel := utils.GetContext(timeout)
		defer cancel()
		service := pb.NewHostServiceClient(conn)
		_, err := service.Delete(ctx, &pb.Reference{Name: aname})

		if err != nil {
			fmt.Printf("%v\n", DecorateError(err, "deletion of host", true))
			deleteErrors <- err
			problems = true
		} else {
			fmt.Printf("Host '%s' deleted\n", aname)
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go hostDeleter(target)
	}

	wg.Wait()
	close(deleteErrors)

	var errorList []string
	for err := range deleteErrors {
		errorList = append(errorList, status.Convert(err).Message())
	}


	if problems {
		formatted := fmt.Errorf("One or more errors detected deleting hosts: [%s]", strings.Join(errorList, ";"))
		return formatted
	}

	return nil
}

// SSHConfig ...
func (h *host) SSHConfig(name string) (*system.SSHConfig, error) {
	if anon, ok := sshCfgCache.Get(name); ok {
		return anon.(*system.SSHConfig), nil
	}
	conn := utils.GetConnection()
	defer conn.Close()
	ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
	defer cancel()
	service := pb.NewHostServiceClient(conn)
	pbSSHCfg, err := service.SSH(ctx, &pb.Reference{Name: name})
	sshCfg := conv.ToSystemSshConfig(pbSSHCfg)
	if err == nil {
		nerr := sshCfgCache.Set(name, sshCfg)
		if nerr != nil {
			return sshCfg, nerr
		}
	}
	return sshCfg, err
}
