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

package services

import (
	"fmt"
	"path"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/satori/go.uuid"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/system/nfs"
	"github.com/CS-SI/SafeScale/utils"
)

//go:generate mockgen -destination=../mocks/mock_nasapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/services ShareAPI

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// ShareAPI defines API to manipulate Shares
type ShareAPI interface {
	Create(name, host, path string) (*propsv1.HostShare, error)
	Delete(name string) error
	List() (map[string]map[string]*propsv1.HostShare, error)
	Mount(name, host, path string) (*propsv1.HostRemoteMount, error)
	Unmount(name, host string) error
	Inspect(name string) (*model.Host, *propsv1.HostShare, map[string]*propsv1.HostRemoteMount, error)
}

// ShareService nas service
type ShareService struct {
	provider *providers.Service
}

// NewShareService creates a ShareService
func NewShareService(api *providers.Service) ShareAPI {
	return &ShareService{
		provider: api,
	}
}

func sanitize(in string) (string, error) {
	sanitized := path.Clean(in)
	if !path.IsAbs(sanitized) {
		return "", logicErr(fmt.Errorf("Exposed path must be absolute"))
	}
	return sanitized, nil
}

// Create a share on host
func (svc *ShareService) Create(shareName, hostName, path string) (*propsv1.HostShare, error) {
	// Check if a share already exists with the same name
	server, _, _, err := svc.Inspect(shareName)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
		default:
			return nil, infraErr(err)
		}
	}
	if server != nil {
		return nil, logicErr(model.ResourceAlreadyExistsError("share", shareName))
	}

	// Sanitize path
	sharePath, err := sanitize(path)
	if err != nil {
		return nil, infraErr(err)
	}

	hostSvc := NewHostService(svc.provider)
	server, err = hostSvc.Get(hostName)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
			return nil, throwErr(err)
		default:
			return nil, infraErr(err)
		}
	}

	// Check if the path to share isn't a remote mount or contains a remote mount
	serverMountsV1 := propsv1.NewHostMounts()
	err = server.Properties.Get(HostProperty.MountsV1, serverMountsV1)
	if err != nil {
		return nil, infraErr(err)
	}
	if _, found := serverMountsV1.RemoteMountsByPath[path]; found {
		return nil, logicErr(fmt.Errorf("path to export '%s' is a mounted share", sharePath))
	}
	for k := range serverMountsV1.RemoteMountsByPath {
		if strings.Index(sharePath, k) == 0 {
			return nil, logicErr(fmt.Errorf("export path '%s' contains a share mounted in '%s'", sharePath, k))
		}
	}

	// Installs NFS Server software if needed
	sshSvc := NewSSHService(svc.provider)
	sshConfig, err := sshSvc.GetConfig(server)
	if err != nil {
		return nil, infraErr(err)
	}
	nfsServer, err := nfs.NewServer(sshConfig)
	if err != nil {
		return nil, infraErr(err)
	}
	serverSharesV1 := propsv1.NewHostShares()
	err = server.Properties.Get(HostProperty.SharesV1, serverSharesV1)
	if err != nil {
		return nil, infraErr(err)
	}
	if len(serverSharesV1.ByID) == 0 {
		// Host doesn't have shares yet, so install NFS
		err = nfsServer.Install()
		if err != nil {
			return nil, infraErr(err)
		}
	}
	err = nfsServer.AddShare(sharePath, "")
	if err != nil {
		return nil, infraErr(err)
	}

	// Create share struct
	share := propsv1.NewHostShare()
	share.Name = shareName
	shareID, err := uuid.NewV4()
	if err != nil {
		return nil, logicErrf(err, "Error creating UUID for share")
	}
	share.ID = shareID.String()
	share.Path = sharePath
	share.Type = "nfs"

	serverSharesV1.ByID[share.ID] = share
	serverSharesV1.ByName[share.Name] = share.ID

	// Updates Host Property propsv1.HostShares
	err = server.Properties.Set(HostProperty.SharesV1, serverSharesV1)
	if err != nil {
		return nil, infraErr(err)
	}

	err = metadata.SaveHost(svc.provider, server)
	if err != nil {
		return nil, logicErrf(err, "Error saving server metadata")
	}
	err = metadata.SaveShare(svc.provider, server.ID, server.Name, share.ID, share.Name)
	if err != nil {
		return nil, infraErr(err)
	}

	return share, nil
}

// Delete a share from host
func (svc *ShareService) Delete(name string) error {
	// Retrieve info about the share
	server, share, _, err := svc.Inspect(name)
	if err != nil {
		return infraErr(err)
	}
	if server == nil {
		return logicErr(model.ResourceNotFoundError(name, "share"))
	}
	serverSharesV1 := propsv1.NewHostShares()
	err = server.Properties.Get(HostProperty.SharesV1, serverSharesV1)
	if err != nil {
		return infraErr(err)
	}

	if len(share.ClientsByName) > 0 {
		var list []string
		for k := range share.ClientsByName {
			list = append(list, k)
		}
		return logicErr(fmt.Errorf("host%s still using it: %s", utils.Plural(len(list)), strings.Join(list, ",")))
	}

	sshSvc := NewSSHService(svc.provider)
	sshConfig, err := sshSvc.GetConfig(server.ID)
	if err != nil {
		return infraErr(err)
	}

	nfsServer, err := nfs.NewServer(sshConfig)
	if err != nil {
		return infraErr(err)
	}
	err = nfsServer.RemoveShare(share.Path)
	if err != nil {
		return infraErr(err)
	}

	delete(serverSharesV1.ByID, share.ID)
	delete(serverSharesV1.ByName, share.Name)
	err = server.Properties.Set(HostProperty.SharesV1, serverSharesV1)
	if err != nil {
		return infraErr(err)
	}

	// Save server metadata
	err = metadata.SaveHost(svc.provider, server)
	if err != nil {
		return infraErr(err)
	}

	// Remove share metadata
	remErr := metadata.RemoveShare(svc.provider, server.ID, server.Name, share.ID, share.Name)
	return infraErr(remErr)
}

// List return the list of all shares from all servers
func (svc *ShareService) List() (map[string]map[string]*propsv1.HostShare, error) {
	shares := map[string]map[string]*propsv1.HostShare{}

	var servers []string
	ms := metadata.NewShare(svc.provider)
	err := ms.Browse(func(hostName string, shareID string) error {
		servers = append(servers, hostName)
		return nil
	})
	if err != nil {
		return nil, logicErrf(err, "Error browsing NASes")
	}

	// Now walks through the hosts acting as Nas
	if len(servers) == 0 {
		return nil, nil
	}

	hostSvc := NewHostService(svc.provider)
	for _, serverID := range servers {
		host, err := hostSvc.Get(serverID)
		if err != nil {
			return nil, infraErr(err)
		}

		hostSharesV1 := propsv1.NewHostShares()
		err = host.Properties.Get(HostProperty.SharesV1, hostSharesV1)
		if err != nil {
			return nil, infraErr(err)
		}

		shares[serverID] = hostSharesV1.ByID
	}
	return shares, nil
}

// Mount a share on a local directory of an host
func (svc *ShareService) Mount(shareName, hostName, path string) (*propsv1.HostRemoteMount, error) {
	// Retrieve info about the share
	server, share, _, err := svc.Inspect(shareName)
	if err != nil {
		err = infraErr(err)
		return nil, err
	}
	if server == nil {
		return nil, model.ResourceNotFoundError("share", shareName)
	}
	// Sanitize path
	mountPath, err := sanitize(path)
	if err != nil {
		return nil, logicErr(fmt.Errorf("invalid mount path '%s': '%s'", path, err))
	}

	var target *model.Host
	if server.Name == hostName || server.ID == hostName {
		target = server
	} else {
		hostSvc := NewHostService(svc.provider)
		target, err = hostSvc.Get(hostName)
		if err != nil {
			switch err.(type) {
			case model.ErrResourceNotFound:
				return nil, infraErr(err)
			default:
				return nil, infraErr(err)
			}
		}
	}

	// Check if share is already mounted
	// Check if there is already volume mounted in the path (or in subpath)
	targetMountsV1 := propsv1.NewHostMounts()
	err = target.Properties.Get(HostProperty.MountsV1, targetMountsV1)
	if err != nil {
		return nil, infraErr(err)
	}
	if s, ok := targetMountsV1.RemoteMountsByShareID[share.ID]; ok {
		return nil, logicErr(fmt.Errorf("already mounted in '%s:%s'", target.Name, targetMountsV1.RemoteMountsByPath[s].Path))
	}
	for _, i := range targetMountsV1.LocalMountsByPath {
		if i.Path == path {
			// Can't mount a share in place of a volume (by convention, nothing technically preventing it)
			return nil, logicErr(fmt.Errorf("there is already a volume in path '%s:%s'", target.Name, path))
		}
	}
	for _, i := range targetMountsV1.RemoteMountsByPath {
		if strings.Index(path, i.Path) == 0 {
			// Can't mount a share inside another share (at least by convention, if not technically)
			return nil, logicErr(fmt.Errorf("there is already a share mounted in '%s:%s'", target.Name, i.Path))
		}
	}

	// Mount the share on host
	serverSharesV1 := propsv1.NewHostShares()
	err = server.Properties.Get(HostProperty.SharesV1, serverSharesV1)
	if err != nil {
		return nil, infraErr(err)
	}
	_, found := serverSharesV1.ByID[serverSharesV1.ByName[shareName]]
	if !found {
		return nil, logicErr(fmt.Errorf("failed to find metadata about share '%s'", shareName))
	}
	shareID := serverSharesV1.ByName[shareName]
	sshSvc := NewSSHService(svc.provider)
	sshConfig, err := sshSvc.GetConfig(target)
	if err != nil {
		return nil, infraErr(err)
	}

	nfsClient, err := nfs.NewNFSClient(sshConfig)
	if err != nil {
		err = infraErr(err)
		return nil, err
	}
	err = nfsClient.Install()
	if err != nil {
		return nil, infraErr(err)
	}

	err = nfsClient.Mount(server.GetAccessIP(), share.Path, mountPath)
	if err != nil {
		return nil, infraErr(err)
	}

	serverSharesV1.ByID[shareID].ClientsByName[target.Name] = target.ID
	serverSharesV1.ByID[shareID].ClientsByID[target.ID] = target.Name
	err = server.Properties.Set(HostProperty.SharesV1, serverSharesV1)
	if err != nil {
		return nil, infraErr(err)
	}

	mount := propsv1.NewHostRemoteMount()
	mount.ShareID = share.ID
	mount.Export = server.GetAccessIP() + ":" + share.Path
	mount.Path = mountPath
	mount.FileSystem = "nfs"
	targetMountsV1.RemoteMountsByPath[mount.Path] = mount
	targetMountsV1.RemoteMountsByShareID[mount.ShareID] = mount.Path
	targetMountsV1.RemoteMountsByExport[mount.Export] = mount.Path
	err = target.Properties.Set(HostProperty.MountsV1, targetMountsV1)
	if err != nil {
		return nil, infraErr(err)
	}

	err = metadata.SaveHost(svc.provider, server)
	if err != nil {
		return nil, infraErr(err)
	}
	if target != server {
		err = metadata.SaveHost(svc.provider, target)
		if err != nil {
			return nil, infraErr(err)
		}
	}
	return mount, nil
}

// Unmount a share from local directory of an host
func (svc *ShareService) Unmount(shareName, hostName string) error {
	server, _, _, err := svc.Inspect(shareName)
	if err != nil {
		return infraErr(err)
	}

	serverSharesV1 := propsv1.NewHostShares()
	err = server.Properties.Get(HostProperty.SharesV1, serverSharesV1)
	if err != nil {
		return infraErr(err)
	}
	shareID, found := serverSharesV1.ByName[shareName]
	if !found {
		return logicErr(fmt.Errorf("failed to find data about share '%s'", shareName))
	}
	// share := serverSharesV1.ByID[shareID]
	// remotePath := server.GetAccessIP() + ":" + share.Path

	var target *model.Host
	if server.Name == hostName || server.ID == hostName {
		target = server
	} else {
		hostSvc := NewHostService(svc.provider)
		target, err = hostSvc.Get(hostName)
		if err != nil {
			switch err.(type) {
			case model.ErrResourceNotFound:
				return err
			default:
				return infraErr(err)
			}
		}
	}

	targetMountsV1 := propsv1.NewHostMounts()
	err = target.Properties.Get(HostProperty.MountsV1, targetMountsV1)
	if err != nil {
		return infraErr(err)
	}
	mount, found := targetMountsV1.RemoteMountsByPath[targetMountsV1.RemoteMountsByShareID[shareID]]
	if !found {
		return logicErr(fmt.Errorf("not mounted on host '%s'", target.Name))
	}

	// Unmount share from client
	sshSvc := NewSSHService(svc.provider)
	sshConfig, err := sshSvc.GetConfig(target.ID)
	if err != nil {
		return infraErr(err)
	}
	nfsClient, err := nfs.NewNFSClient(sshConfig)
	if err != nil {
		return infraErr(err)
	}
	err = nfsClient.Unmount(server.GetAccessIP(), mount.Path)
	if err != nil {
		return infraErr(err)
	}

	// Remove mount from mount list
	delete(targetMountsV1.RemoteMountsByShareID, mount.ShareID)
	delete(targetMountsV1.RemoteMountsByPath, mount.Path)
	err = target.Properties.Set(HostProperty.MountsV1, targetMountsV1)
	if err != nil {
		return infraErr(err)
	}

	// Remove host from client lists of the share
	delete(serverSharesV1.ByID[shareID].ClientsByName, target.Name)
	delete(serverSharesV1.ByID[shareID].ClientsByID, target.ID)
	err = server.Properties.Set(HostProperty.SharesV1, serverSharesV1)
	if err != nil {
		return infraErr(err)
	}

	// Saves metadata
	err = metadata.SaveHost(svc.provider, server)
	if err != nil {
		return infraErr(err)
	}
	if server != target {
		err = metadata.SaveHost(svc.provider, target)
		if err != nil {
			return infraErr(err)
		}
	}

	return nil
}

// Inspect returns the host and share corresponding to 'shareName'
func (svc *ShareService) Inspect(shareName string) (*model.Host, *propsv1.HostShare, map[string]*propsv1.HostRemoteMount, error) {
	hostName, err := metadata.LoadShare(svc.provider, shareName)
	if err != nil {
		err = infraErr(errors.Wrap(err, "error loading share metadata"))
		return nil, nil, nil, err
	}
	if hostName == "" {
		return nil, nil, nil, logicErr(model.ResourceNotFoundError("share", shareName))
	}

	hostSvc := NewHostService(svc.provider)
	server, err := hostSvc.Get(hostName)
	if err != nil {
		return nil, nil, nil, infraErr(err)
	}
	serverSharesV1 := propsv1.NewHostShares()
	err = server.Properties.Get(HostProperty.SharesV1, serverSharesV1)
	if err != nil {
		return nil, nil, nil, infraErr(err)
	}

	shareID, found := serverSharesV1.ByName[shareName]
	if !found {
		shareID = shareName
		_, found = serverSharesV1.ByID[shareID]
	}
	if !found {
		return nil, nil, nil, infraErr(err)
	}
	share := serverSharesV1.ByID[shareID]

	mounts := map[string]*propsv1.HostRemoteMount{}
	clientMountsV1 := propsv1.NewHostMounts()
	for k := range share.ClientsByName {
		client, err := hostSvc.Get(k)
		if err != nil {
			switch err.(type) {
			case model.ErrResourceNotFound:
				log.Errorf("Host '%s' not found", k)
			default:
				log.Errorf("Failed to find data for host '%s': %v", k, err)
			}
			continue
		}

		err = client.Properties.Get(HostProperty.MountsV1, clientMountsV1)
		if err != nil {
			log.Errorln(err.Error())
			continue
		}
		mountPath, ok := clientMountsV1.RemoteMountsByShareID[shareID]
		if !ok {
			continue
		}
		mount := clientMountsV1.RemoteMountsByPath[mountPath]
		mounts[client.Name] = &propsv1.HostRemoteMount{
			Path:       mount.Path,
			FileSystem: mount.FileSystem,
		}
	}
	return server, serverSharesV1.ByID[shareID], mounts, nil
}

func (svc *ShareService) findShare(shareName string) (string, error) {
	hostName, err := metadata.LoadShare(svc.provider, shareName)
	if err != nil {
		return "", infraErrf(err, "Failed to load Share metadata '%s'", shareName)
	}
	return hostName, nil
}
