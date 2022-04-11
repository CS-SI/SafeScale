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

package client

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	"github.com/CS-SI/SafeScale/v21/lib/server/utils"
	clitools "github.com/CS-SI/SafeScale/v21/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

// share is the part of the safescale client handling Shares
type share struct {
	session *Session
}

// Create ...
func (n share) Create(def *protocol.ShareDefinition, timeout time.Duration) error {
	n.session.Connect()
	defer n.session.Disconnect()
	service := protocol.NewShareServiceClient(n.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	_, err := service.Create(newCtx, def)
	if err != nil {
		return DecorateTimeoutError(err, "creation of share", true)
	}
	return nil
}

// Delete deletes a share
func (n share) Delete(names []string, timeout time.Duration) error {
	n.session.Connect()
	defer n.session.Disconnect()

	service := protocol.NewShareServiceClient(n.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
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

	shareDeleter := func(aname string) {
		var crash error
		defer fail.OnPanic(&crash)

		defer wg.Done()

		if _, xerr := service.Delete(newCtx, &protocol.Reference{Name: aname}); xerr != nil {
			mutex.Lock()
			errs = append(errs, xerr.Error())
			mutex.Unlock() // nolint
		}
	}

	wg.Add(len(names))
	for _, target := range names {
		go shareDeleter(target)
	}
	wg.Wait()

	if len(errs) > 0 {
		return clitools.ExitOnRPC(strings.Join(errs, ", "))
	}

	return nil
}

// List ...
func (n share) List(timeout time.Duration) (*protocol.ShareList, error) {
	n.session.Connect()
	defer n.session.Disconnect()
	service := protocol.NewShareServiceClient(n.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	list, err := service.List(newCtx, &protocol.Reference{})
	if err != nil {
		return nil, DecorateTimeoutError(err, "list of shares", true)
	}
	return list, nil
}

// Mount ...
func (n share) Mount(def *protocol.ShareMountDefinition, timeout time.Duration) error {
	n.session.Connect()
	defer n.session.Disconnect()
	service := protocol.NewShareServiceClient(n.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	_, err := service.Mount(newCtx, def)
	if err != nil {
		return DecorateTimeoutError(err, "mount of share", true)
	}
	return nil
}

// Unmount ...
func (n share) Unmount(def *protocol.ShareMountDefinition, timeout time.Duration) error {
	n.session.Connect()
	defer n.session.Disconnect()
	service := protocol.NewShareServiceClient(n.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	_, err := service.Unmount(newCtx, def)
	if err != nil {
		return DecorateTimeoutError(err, "unmount of share", true)
	}
	return nil
}

// Inspect ...
func (n share) Inspect(name string, timeout time.Duration) (*protocol.ShareMountList, error) {
	n.session.Connect()
	defer n.session.Disconnect()
	service := protocol.NewShareServiceClient(n.session.connection)
	ctx, xerr := utils.GetContext(true)
	if xerr != nil {
		return nil, xerr
	}

	// finally, using context
	newCtx := ctx
	if timeout != 0 {
		aCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		newCtx = aCtx
	}

	list, err := service.Inspect(newCtx, &protocol.Reference{Name: name})
	if err != nil {
		return nil, DecorateTimeoutError(err, "inspection of share", true)
	}
	return list, nil
}
