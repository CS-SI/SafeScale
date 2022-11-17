/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package cmdline

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/common"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// labelConsumer is the part of safescale client handling Labels/Tags
type labelConsumer struct {
	session *Session
}

// List returns a list of Labels (selectTags=false) or Tags (selectTags=true)
func (t labelConsumer) List(selectTags bool, timeout time.Duration) (*protocol.LabelListResponse, error) {
	t.session.Connect()
	defer t.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
	if xerr != nil {
		return nil, xerr
	}

	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.LabelListRequest{
		Organization: t.session.currentOrganization,
		Project:      t.session.currentProject,
		TenantId:     t.session.currentTenant,
		Tags:         selectTags,
	}
	service := protocol.NewLabelServiceClient(t.session.connection)
	return service.List(newCtx, req)
}

// Inspect ...
func (t labelConsumer) Inspect(name string, selectTag bool, timeout time.Duration) (*protocol.LabelInspectResponse, error) {
	t.session.Connect()
	defer t.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
	if xerr != nil {
		return nil, xerr
	}

	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.LabelInspectRequest{
		Label: &protocol.Reference{
			Organization: t.session.currentOrganization,
			Project:      t.session.currentProject,
			TenantId:     t.session.currentTenant,
			Name:         name,
		},
		IsTag: selectTag,
	}
	service := protocol.NewLabelServiceClient(t.session.connection)
	return service.Inspect(newCtx, req)
}

// Delete ...
func (t labelConsumer) Delete(names []string, selectTags bool, timeout time.Duration) error {
	t.session.Connect()
	defer t.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
	if xerr != nil {
		return xerr
	}

	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	var (
		mutex sync.Mutex
		wg    sync.WaitGroup
		errs  []string
	)

	service := protocol.NewLabelServiceClient(t.session.connection)

	labelDeleter := func(aname string) {
		var crash error
		defer fail.OnPanic(&crash)

		defer wg.Done()

		req := &protocol.LabelInspectRequest{
			Label: &protocol.Reference{
				Organization: t.session.currentOrganization,
				Project:      t.session.currentProject,
				TenantId:     t.session.currentTenant,
				Name:         aname,
			},
			IsTag: selectTags,
		}
		_, err := service.Delete(newCtx, req)

		if err != nil {
			mutex.Lock()
			defer mutex.Unlock()
			errs = append(errs, err.Error())
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go labelDeleter(target)
	}
	wg.Wait()

	if len(errs) > 0 {
		return cli.ExitOnRPC(strings.Join(errs, ", "))
	}
	return nil

}

// Create requests creation of a new Label
func (t labelConsumer) Create(name string, hasDefault bool, defaultValue string, timeout time.Duration) (*protocol.LabelInspectResponse, error) {
	t.session.Connect()
	defer t.session.Disconnect()

	ctx, xerr := common.ContextForGRPC(true)
	if xerr != nil {
		return nil, xerr
	}

	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	req := &protocol.LabelCreateRequest{
		Name:         name,
		HasDefault:   hasDefault,
		DefaultValue: defaultValue,
		Organization: t.session.currentOrganization,
		Project:      t.session.currentProject,
		TenantId:     t.session.currentTenant,
	}
	service := protocol.NewLabelServiceClient(t.session.connection)
	return service.Create(newCtx, req)
}