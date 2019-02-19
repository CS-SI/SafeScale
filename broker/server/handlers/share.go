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

package handlers

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	uuid "github.com/satori/go.uuid"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/system/nfs"
	"github.com/CS-SI/SafeScale/utils"
)

//go:generate mockgen -destination=../mocks/mock_nasapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/handlers ShareAPI

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// ShareAPI defines API to manipulate Shares
type ShareAPI interface {
	Create(ctx context.Context, shareName, hostName, path string, secutityModes []string, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool) (*propsv1.HostShare, error)
	ForceInspect(ctx context.Context, name string) (*model.Host, *propsv1.HostShare, map[string]*propsv1.HostRemoteMount, error)
	Inspect(ctx context.Context, name string) (*model.Host, *propsv1.HostShare, map[string]*propsv1.HostRemoteMount, error)
	Delete(ctx context.Context, name string) error
	List(ctx context.Context) (map[string]map[string]*propsv1.HostShare, error)
	Mount(ctx context.Context, name, host, path string, withCache bool) (*propsv1.HostRemoteMount, error)
	Unmount(ctx context.Context, name, host string) error
}

// ShareHandler nas service
type ShareHandler struct {
	provider *providers.Service
}

// NewShareHandler creates a ShareHandler
func NewShareHandler(api *providers.Service) ShareAPI {
	return &ShareHandler{
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
func (svc *ShareHandler) Create(ctx context.Context, shareName, hostName, path string, secutityModes []string, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool) (*propsv1.HostShare, error) {
	// Check if a share already exists with the same name
	server, _, _, err := svc.Inspect(ctx, shareName)
	if err != nil {
		if _, ok := err.(model.ErrResourceNotFound); !ok {
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

	hostHandler := NewHostHandler(svc.provider)
	server, err = hostHandler.Inspect(ctx, hostName)
	if err != nil {
		return nil, throwErr(err)
	}

	// Check if the path to share isn't a remote mount or contains a remote mount
	err = server.Properties.LockForRead(HostProperty.MountsV1).ThenUse(func(v interface{}) error {
		serverMountsV1 := v.(*propsv1.HostMounts)
		if _, found := serverMountsV1.RemoteMountsByPath[path]; found {
			return logicErr(fmt.Errorf("path to export '%s' is a mounted share", sharePath))
		}
		for k := range serverMountsV1.RemoteMountsByPath {
			if strings.Index(sharePath, k) == 0 {
				return logicErr(fmt.Errorf("export path '%s' contains a share mounted in '%s'", sharePath, k))
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Installs NFS Server software if needed
	sshHandler := NewSSHHandler(svc.provider)
	sshConfig, err := sshHandler.GetConfig(ctx, server)
	if err != nil {
		return nil, infraErr(err)
	}
	nfsServer, err := nfs.NewServer(sshConfig)
	if err != nil {
		return nil, infraErr(err)
	}

	err = server.Properties.LockForRead(HostProperty.SharesV1).ThenUse(func(v interface{}) error {
		serverSharesV1 := v.(*propsv1.HostShares)
		if len(serverSharesV1.ByID) == 0 {
			// Host doesn't have shares yet, so install NFS
			err = nfsServer.Install()
			if err != nil {
				return infraErr(err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = nfsServer.AddShare(sharePath, secutityModes, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck)
	if err != nil {
		return nil, infraErr(err)
	}
	defer func() {
		if err != nil {
			err2 := nfsServer.RemoveShare(sharePath)
			if err2 != nil {
				log.Warn("Failed to RemoveShare")
			}
		}
	}()

	var share *propsv1.HostShare

	// Updates Host Property propsv1.HostShares
	err = server.Properties.LockForWrite(HostProperty.SharesV1).ThenUse(func(v interface{}) error {
		serverSharesV1 := v.(*propsv1.HostShares)

		share = propsv1.NewHostShare()
		share.Name = shareName
		shareID, err := uuid.NewV4()
		if err != nil {
			return logicErrf(err, "Error creating UUID for share")
		}
		share.ID = shareID.String()
		share.Path = sharePath
		share.Type = "nfs"

		serverSharesV1.ByID[share.ID] = share
		serverSharesV1.ByName[share.Name] = share.ID

		return nil
	})
	if err != nil {
		return nil, err
	}

	err = metadata.SaveHost(svc.provider, server)
	if err != nil {
		return nil, logicErrf(err, "Error saving server metadata")
	}
	defer func() {
		if err != nil {
			err2 := server.Properties.LockForWrite(HostProperty.SharesV1).ThenUse(func(v interface{}) error {
				serverSharesV1 := v.(*propsv1.HostShares)
				delete(serverSharesV1.ByID, share.ID)
				delete(serverSharesV1.ByName, share.Name)
				return nil
			})
			if err2 != nil {
				log.Warnf("Failed to set shares metadata of host %s", hostName)
			}
			err2 = metadata.SaveHost(svc.provider, server)
			if err2 != nil {
				log.Warnf("Failed to save metadata of host %s", hostName)
			}
		}
	}()
	err = metadata.SaveShare(svc.provider, server.ID, server.Name, share.ID, share.Name)
	if err != nil {
		return nil, infraErr(err)
	}
	defer func() {
		if err != nil {
			err2 := metadata.RemoveShare(svc.provider, server.ID, server.Name, share.ID, share.Name)
			if err2 != nil {
				log.Warnf("Failed to delete metadata of share %s", share.Name)
			}
		}
	}()

	select {
	case <-ctx.Done():
		log.Warnf("Share creation canceled by broker")
		err = fmt.Errorf("Share creation canceld by broker")
		return nil, err
	default:
	}

	return share, nil
}

// Delete a share from host
func (svc *ShareHandler) Delete(ctx context.Context, name string) error {
	// Retrieve info about the share
	server, share, _, err := svc.ForceInspect(ctx, name)
	if err != nil {
		return throwErr(err)
	}
	if server == nil {
		return throwErrf("Delete share: unable to inspect host '%s'", name)
	}
	if share == nil {
		return throwErrf("Delete share: unable to found share of host '%s'", name)
	}

	err = server.Properties.LockForWrite(HostProperty.SharesV1).ThenUse(func(v interface{}) error {
		serverSharesV1 := v.(*propsv1.HostShares)
		if len(share.ClientsByName) > 0 {
			var list []string
			for k := range share.ClientsByName {
				list = append(list, "'"+k+"'")
			}
			return logicErr(fmt.Errorf("still used by: %s", strings.Join(list, ",")))
		}

		sshHandler := NewSSHHandler(svc.provider)
		sshConfig, err := sshHandler.GetConfig(ctx, server.ID)
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
		return nil
	})
	if err != nil {
		return err
	}

	// Save server metadata
	err = metadata.SaveHost(svc.provider, server)
	if err != nil {
		return infraErr(err)
	}

	// Remove share metadata
	err = metadata.RemoveShare(svc.provider, server.ID, server.Name, share.ID, share.Name)
	if err != nil {
		return infraErr(err)
	}

	select {
	case <-ctx.Done():
		log.Warnf("Share delete canceled by broker")
		_, err = svc.Create(context.Background(), share.Name, server.Name, share.Path, []string{}, false, false, false, false, false, false, false)
		if err != nil {
			return fmt.Errorf("Failed to stop Share deletion")
		}
		return fmt.Errorf("Share deletion canceld by broker")
	default:
	}

	return nil
}

// List return the list of all shares from all servers
func (svc *ShareHandler) List(ctx context.Context) (map[string]map[string]*propsv1.HostShare, error) {
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
		return shares, nil
	}

	hostSvc := NewHostHandler(svc.provider)
	for _, serverID := range servers {
		host, err := hostSvc.Inspect(ctx, serverID)
		if err != nil {
			return nil, infraErr(err)
		}

		err = host.Properties.LockForRead(HostProperty.SharesV1).ThenUse(func(v interface{}) error {
			hostSharesV1 := v.(*propsv1.HostShares)
			shares[serverID] = hostSharesV1.ByID
			return nil
		})
		if err != nil {
			return nil, infraErr(err)
		}
	}
	return shares, nil
}

// Mount a share on a local directory of an host
func (svc *ShareHandler) Mount(ctx context.Context, shareName, hostName, path string, withCache bool) (*propsv1.HostRemoteMount, error) {
	// Retrieve info about the share
	server, share, _, err := svc.Inspect(ctx, shareName)
	if err != nil {
		return nil, throwErr(err)
	}
	if share == nil {
		return nil, model.ResourceNotFoundError("share", shareName)
	}
	if server == nil {
		return nil, model.ResourceNotFoundError("host", hostName)
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
		hostSvc := NewHostHandler(svc.provider)
		target, err = hostSvc.Inspect(ctx, hostName)
		if err != nil {
			return nil, throwErr(err)
		}
	}

	// Check if share is already mounted
	// Check if there is already volume mounted in the path (or in subpath)
	err = target.Properties.LockForRead(HostProperty.MountsV1).ThenUse(func(v interface{}) error {
		targetMountsV1 := v.(*propsv1.HostMounts)
		if s, ok := targetMountsV1.RemoteMountsByShareID[share.ID]; ok {
			return logicErr(fmt.Errorf("already mounted in '%s:%s'", target.Name, targetMountsV1.RemoteMountsByPath[s].Path))
		}
		for _, i := range targetMountsV1.LocalMountsByPath {
			if i.Path == path {
				// Can't mount a share in place of a volume (by convention, nothing technically preventing it)
				return logicErr(fmt.Errorf("there is already a volume in path '%s:%s'", target.Name, path))
			}
		}
		for _, i := range targetMountsV1.RemoteMountsByPath {
			if strings.Index(path, i.Path) == 0 {
				// Can't mount a share inside another share (at least by convention, if not technically)
				return logicErr(fmt.Errorf("there is already a share mounted in '%s:%s'", target.Name, i.Path))
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	export := ""
	err = target.Properties.LockForRead(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
		if v.(*propsv1.HostNetwork).DefaultGatewayPrivateIP == server.GetPrivateIP() {
			export = server.GetPrivateIP() + ":" + share.Path
		} else {
			export = server.GetAccessIP() + ":" + share.Path
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Mount the share on host
	err = server.Properties.LockForWrite(HostProperty.SharesV1).ThenUse(func(v interface{}) error {
		serverSharesV1 := v.(*propsv1.HostShares)
		_, found := serverSharesV1.ByID[serverSharesV1.ByName[shareName]]
		if !found {
			return logicErr(fmt.Errorf("failed to find metadata about share '%s'", shareName))
		}
		shareID := serverSharesV1.ByName[shareName]
		sshHandler := NewSSHHandler(svc.provider)
		sshConfig, err := sshHandler.GetConfig(ctx, target)
		if err != nil {
			return infraErr(err)
		}

		nfsClient, err := nfs.NewNFSClient(sshConfig)
		if err != nil {
			err = infraErr(err)
			return err
		}
		err = nfsClient.Install()
		if err != nil {
			return infraErr(err)
		}

		err = nfsClient.Mount(export, mountPath, withCache)
		if err != nil {
			return infraErr(err)
		}

		serverSharesV1.ByID[shareID].ClientsByName[target.Name] = target.ID
		serverSharesV1.ByID[shareID].ClientsByID[target.ID] = target.Name
		return nil
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			sshHandler := NewSSHHandler(svc.provider)
			sshConfig, err := sshHandler.GetConfig(ctx, target)
			if err != nil {
				log.Warn(infraErr(err).Error())
			}

			nfsClient, err := nfs.NewNFSClient(sshConfig)
			if err != nil {
				err = infraErr(err)
				log.Warn(err.Error())
			}
			err = nfsClient.Install()
			if err != nil {
				log.Warn(infraErr(err).Error())
			}

			err = nfsClient.Unmount(export)
			if err != nil {
				log.Warn(infraErr(err).Error())
			}
		}
	}()

	var mount *propsv1.HostRemoteMount
	err = target.Properties.LockForWrite(HostProperty.MountsV1).ThenUse(func(v interface{}) error {
		targetMountsV1 := v.(*propsv1.HostMounts)
		// Make sure the HostMounts is correctly init if there are no mount yet
		if !target.Properties.Lookup(HostProperty.MountsV1) {
			targetMountsV1.Reset()
		}
		mount = propsv1.NewHostRemoteMount()
		mount.ShareID = share.ID
		mount.Export = export
		mount.Path = mountPath
		mount.FileSystem = "nfs"
		targetMountsV1.RemoteMountsByPath[mount.Path] = mount
		targetMountsV1.RemoteMountsByShareID[mount.ShareID] = mount.Path
		targetMountsV1.RemoteMountsByExport[mount.Export] = mount.Path
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = metadata.SaveHost(svc.provider, server)
	if err != nil {
		return nil, infraErr(err)
	}
	defer func() {
		if err != nil {
			err2 := server.Properties.LockForWrite(HostProperty.SharesV1).ThenUse(func(v interface{}) error {
				serverSharesV1 := v.(*propsv1.HostShares)
				delete(serverSharesV1.ByID[serverSharesV1.ByName[shareName]].ClientsByName, target.Name)
				delete(serverSharesV1.ByID[serverSharesV1.ByName[shareName]].ClientsByID, target.ID)
				return nil
			})
			if err2 != nil {
				log.Warnf("Failed to remove mounted share %s from host %s metadatas", shareName, server.Name)
			}
			err2 = metadata.SaveHost(svc.provider, server)
			if err2 != nil {
				log.Warnf("Failed to save host %s metadatas : %s", server.Name, err2.Error())
			}
		}
	}()

	if target != server {
		err = metadata.SaveHost(svc.provider, target)
		if err != nil {
			return nil, infraErr(err)
		}
	}
	defer func() {
		if err != nil {
			err2 := target.Properties.LockForWrite(HostProperty.MountsV1).ThenUse(func(v interface{}) error {
				targetMountsV1 := v.(*propsv1.HostMounts)
				delete(targetMountsV1.RemoteMountsByShareID, mount.ShareID)
				delete(targetMountsV1.RemoteMountsByPath, mount.Path)
				delete(targetMountsV1.RemoteMountsByExport, mount.Export)
				return nil
			})
			if err2 != nil {
				log.Warnf("Failed to remove mounted share %s from host %s metadatas", shareName, hostName)
			}
			err2 = metadata.SaveHost(svc.provider, target)
			if err2 != nil {
				log.Warnf("Failed to save host %s metadatas : %s", hostName, err2.Error())
			}
		}
	}()

	select {
	case <-ctx.Done():
		log.Warnf("Share mount canceled by broker")
		err = fmt.Errorf("Share mount canceld by broker")
		return nil, err
	default:
	}

	return mount, nil
}

// Unmount a share from local directory of an host
func (svc *ShareHandler) Unmount(ctx context.Context, shareName, hostName string) error {
	server, share, _, err := svc.ForceInspect(ctx, shareName)
	if err != nil {
		return throwErr(err)
	}

	var shareID string
	err = server.Properties.LockForRead(HostProperty.SharesV1).ThenUse(func(v interface{}) error {
		serverSharesV1 := v.(*propsv1.HostShares)
		var found bool
		shareID, found = serverSharesV1.ByName[shareName]
		if !found {
			return logicErr(fmt.Errorf("failed to find data about share '%s'", shareName))
		}
		// share := serverSharesV1.ByID[shareID]
		// remotePath := server.GetAccessIP() + ":" + share.Path
		return nil
	})
	if err != nil {
		return err
	}

	var target *model.Host
	var mount_path string
	if server.Name == hostName || server.ID == hostName {
		target = server
	} else {
		hostSvc := NewHostHandler(svc.provider)
		target, err = hostSvc.ForceInspect(ctx, hostName)
		if err != nil {
			return throwErr(err)
		}
	}

	err = target.Properties.LockForWrite(HostProperty.MountsV1).ThenUse(func(v interface{}) error {
		targetMountsV1 := v.(*propsv1.HostMounts)
		mount, found := targetMountsV1.RemoteMountsByPath[targetMountsV1.RemoteMountsByShareID[shareID]]
		if !found {
			return logicErr(fmt.Errorf("not mounted on host '%s'", target.Name))
		}

		// Unmount share from client
		sshHandler := NewSSHHandler(svc.provider)
		sshConfig, err := sshHandler.GetConfig(ctx, target.ID)
		if err != nil {
			return infraErr(err)
		}
		nfsClient, err := nfs.NewNFSClient(sshConfig)
		if err != nil {
			return infraErr(err)
		}
		err = nfsClient.Unmount(server.GetAccessIP() + ":" + share.Path)
		if err != nil {
			return infraErr(err)
		}

		// Remove mount from mount list
		mount_path = mount.Path
		delete(targetMountsV1.RemoteMountsByShareID, mount.ShareID)
		delete(targetMountsV1.RemoteMountsByPath, mount_path)
		return nil
	})
	if err != nil {
		return err
	}

	// Remove host from client lists of the share
	err = server.Properties.LockForWrite(HostProperty.SharesV1).ThenUse(func(v interface{}) error {
		serverSharesV1 := v.(*propsv1.HostShares)
		delete(serverSharesV1.ByID[shareID].ClientsByName, target.Name)
		delete(serverSharesV1.ByID[shareID].ClientsByID, target.ID)
		return nil
	})
	if err != nil {
		return err
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

	select {
	case <-ctx.Done():
		log.Warnf("Share unmount canceled by broker")
		_, err = svc.Mount(context.Background(), shareName, hostName, mount_path, false)
		if err != nil {
			return fmt.Errorf("Failed to stop Share unmounting")
		}
		return fmt.Errorf("Share unmounting canceld by broker")
	default:
	}

	return nil
}

// ForceInspect returns the host and share corresponding to 'shareName'
func (svc *ShareHandler) ForceInspect(ctx context.Context, shareName string) (*model.Host, *propsv1.HostShare, map[string]*propsv1.HostRemoteMount, error) {
	host, share, mounts, err := svc.Inspect(ctx, shareName)
	if err != nil {
		return nil, nil, nil, throwErr(err)
	}
	if host == nil {
		return nil, nil, nil, logicErr(fmt.Errorf("failed to find host exporting the share '%s'", shareName))
	}
	return host, share, mounts, nil
}

// Inspect returns the host and share corresponding to 'shareName'
// If share isn't found, return (nil, nil, nil, model.ErrResourceNotFound)
func (svc *ShareHandler) Inspect(ctx context.Context, shareName string) (*model.Host, *propsv1.HostShare, map[string]*propsv1.HostRemoteMount, error) {
	hostName, err := metadata.LoadShare(svc.provider, shareName)
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			return nil, nil, nil, model.ResourceNotFoundError("share", shareName)
		}
		return nil, nil, nil, infraErr(errors.Wrap(err, "error loading share metadata"))
	}
	if hostName == "" {
		return nil, nil, nil, infraErr(errors.Wrap(err, fmt.Sprintf("failed to find host sharing '%s'", shareName)))
	}

	hostSvc := NewHostHandler(svc.provider)
	server, err := hostSvc.ForceInspect(ctx, hostName)
	if err != nil {
		return nil, nil, nil, throwErr(err)
	}

	var (
		shareID string
		share   *propsv1.HostShare
	)
	err = server.Properties.LockForRead(HostProperty.SharesV1).ThenUse(func(v interface{}) error {
		serverSharesV1 := v.(*propsv1.HostShares)
		var found bool
		shareID, found = serverSharesV1.ByName[shareName]
		if !found {
			shareID = shareName
			_, found = serverSharesV1.ByID[shareID]
		}
		if !found {
			return infraErr(model.ResourceNotFoundError("share", fmt.Sprintf("no share named '%s'", shareName)))
		}
		share = serverSharesV1.ByID[shareID]
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}

	mounts := map[string]*propsv1.HostRemoteMount{}
	for k := range share.ClientsByName {
		client, err := hostSvc.Inspect(ctx, k)
		if err != nil {
			log.Errorf("%+v", err)
			continue
		}

		err = client.Properties.LockForRead(HostProperty.MountsV1).ThenUse(func(v interface{}) error {
			clientMountsV1 := v.(*propsv1.HostMounts)
			mountPath, ok := clientMountsV1.RemoteMountsByShareID[shareID]
			if ok {
				mount := clientMountsV1.RemoteMountsByPath[mountPath]
				mounts[client.Name] = &propsv1.HostRemoteMount{
					Path:       mount.Path,
					FileSystem: mount.FileSystem,
				}
			}
			return nil
		})
		if err != nil {
			log.Errorln(err.Error())
			continue
		}
	}
	return server, share, mounts, nil
}

func (svc *ShareHandler) findShare(shareName string) (string, error) {
	hostName, err := metadata.LoadShare(svc.provider, shareName)
	if err != nil {
		return "", infraErrf(err, "Failed to load Share metadata '%s'", shareName)
	}
	return hostName, nil
}
