/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"strings"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
)

// publicIP is the part of safescale client handling Public IP
type publicIP struct {
	// session is not used currently
	session *Session
}

// List ...
func (pi publicIP) List(all bool, timeout time.Duration) (*protocol.PublicIPListResponse, error) {
	pi.session.Connect()
	defer pi.session.Disconnect()
	service := protocol.NewPublicIPServiceClient(pi.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	req := &protocol.PublicIPListRequest{
		TenantId: pi.session.tenantName,
		All:      all,
	}
	return service.List(ctx, req)
}

// Delete deletes several publicips at the same time in goroutines
func (pi publicIP) Delete(names []string, force bool, timeout time.Duration) error {
	pi.session.Connect()
	defer pi.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	var (
		mutex sync.Mutex
		wg    sync.WaitGroup
		errs  []string
	)

	service := protocol.NewPublicIPServiceClient(pi.session.connection)

	publicipDeleter := func(aname string) {
		defer wg.Done()

		req := &protocol.PublicIPDeleteRequest{
			TenantId: pi.session.tenantName,
			Ip:       &protocol.Reference{Name: aname},
			Force:    force,
		}
		_, err := service.Delete(ctx, req)

		if err != nil {
			mutex.Lock()
			errs = append(errs, err.Error())
			mutex.Unlock()
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go publicipDeleter(target)
	}
	wg.Wait()

	if len(errs) > 0 {
		return clitools.ExitOnRPC(strings.Join(errs, ", "))
	}
	return nil

}

// Inspect ...
func (pi publicIP) Inspect(name string, timeout time.Duration) (*protocol.PublicIPResponse, error) {
	pi.session.Connect()
	defer pi.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewPublicIPServiceClient(pi.session.connection)

	req := &protocol.Reference{
		TenantId: pi.session.tenantName,
		Name:     name,
	}
	return service.Inspect(ctx, req)
}

// Create ...
func (pi publicIP) Create(name string, ipType ipversion.Enum, description string, timeout time.Duration) (*protocol.PublicIPResponse, error) {
	pi.session.Connect()
	defer pi.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	service := protocol.NewPublicIPServiceClient(pi.session.connection)

	req := &protocol.PublicIPCreateRequest{
		TenantId:    pi.session.tenantName,
		Name:        name,
		Type:        ipType.String(),
		Description: description,
	}
	return service.Create(ctx, req)
}

// Bind ...
func (pi publicIP) Bind(piRef, hRef string, timeout time.Duration) error {
	pi.session.Connect()
	defer pi.session.Disconnect()

	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	service := protocol.NewPublicIPServiceClient(pi.session.connection)

	req := &protocol.PublicIPBindRequest{
		TenantId: pi.session.tenantName,
		Ip:       &protocol.Reference{Name: piRef},
		Host:     &protocol.Reference{Name: hRef},
	}
	_, err := service.Bind(ctx, req)
	return err
}

// Unbind ...
func (pi publicIP) Unbind(piRef, hRef string, timeout time.Duration) error {
	pi.session.Connect()
	defer pi.session.Disconnect()

	service := protocol.NewPublicIPServiceClient(pi.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	req := &protocol.PublicIPBindRequest{
		TenantId: pi.session.tenantName,
		Ip:       &protocol.Reference{Name: piRef},
		Host:     &protocol.Reference{Name: hRef},
	}
	_, err := service.Unbind(ctx, req)
	return err
}
