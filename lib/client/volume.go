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
    "github.com/CS-SI/SafeScale/lib/server/utils"
    clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
)

// volume is the part of safescale client handing volumes
type volume struct {
    // session is not used currently
    session *Session
}

// List ...
func (v volume) List(all bool, timeout time.Duration) (*protocol.VolumeListResponse, error) {
    v.session.Connect()
    defer v.session.Disconnect()

    ctx, xerr := utils.GetContext(true)
    if xerr != nil {
        return nil, xerr
    }

    service := protocol.NewVolumeServiceClient(v.session.connection)
    return service.List(ctx, &protocol.VolumeListRequest{All: all})
}

// Inspect ...
func (v volume) Inspect(name string, timeout time.Duration) (*protocol.VolumeInspectResponse, error) {
    v.session.Connect()
    defer v.session.Disconnect()

    ctx, xerr := utils.GetContext(true)
    if xerr != nil {
        return nil, xerr
    }

    service := protocol.NewVolumeServiceClient(v.session.connection)
    return service.Inspect(ctx, &protocol.Reference{Name: name})
}

// Delete ...
func (v volume) Delete(names []string, timeout time.Duration) error {
    v.session.Connect()
    defer v.session.Disconnect()

    ctx, xerr := utils.GetContext(true)
    if xerr != nil {
        return xerr
    }

    var (
        mutex sync.Mutex
        wg    sync.WaitGroup
        errs  []string
    )

    service := protocol.NewVolumeServiceClient(v.session.connection)

    volumeDeleter := func(aname string) {
        defer wg.Done()
        _, err := service.Delete(ctx, &protocol.Reference{Name: aname})

        if err != nil {
            mutex.Lock()
            errs = append(errs, err.Error())
            mutex.Unlock()
        }
    }

    wg.Add(len(names))
    for _, target := range names {
        go volumeDeleter(target)
    }
    wg.Wait()

    if len(errs) > 0 {
        return clitools.ExitOnRPC(strings.Join(errs, ", "))
    }
    return nil

}

// Create ...
func (v volume) Create(def *protocol.VolumeCreateRequest, timeout time.Duration) (*protocol.VolumeInspectResponse, error) {
    v.session.Connect()
    defer v.session.Disconnect()

    ctx, xerr := utils.GetContext(true)
    if xerr != nil {
        return nil, xerr
    }

    service := protocol.NewVolumeServiceClient(v.session.connection)
    return service.Create(ctx, def)
}

// Attach ...
func (v volume) Attach(def *protocol.VolumeAttachmentRequest, timeout time.Duration) error {
    v.session.Connect()
    defer v.session.Disconnect()

    ctx, xerr := utils.GetContext(true)
    if xerr != nil {
        return xerr
    }

    service := protocol.NewVolumeServiceClient(v.session.connection)
    _, err := service.Attach(ctx, def)
    return err

}

// Detach ...
func (v volume) Detach(volumeName string, hostName string, timeout time.Duration) error {
    v.session.Connect()
    defer v.session.Disconnect()

    ctx, xerr := utils.GetContext(true)
    if xerr != nil {
        return xerr
    }

    service := protocol.NewVolumeServiceClient(v.session.connection)
    _, err := service.Detach(ctx, &protocol.VolumeDetachmentRequest{
        Volume: &protocol.Reference{Name: volumeName},
        Host:   &protocol.Reference{Name: hostName},
    })
    return err
}
