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

package converters

// Contains functions that are used to convert from property

import (
    "github.com/CS-SI/SafeScale/lib/protocol"
    propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
)

// ShareFromPropertyToProtocol convert a share from host to protocol message
func ShareFromPropertyToProtocol(hostName string, share *propertiesv1.HostShare) *protocol.ShareDefinition {
    return &protocol.ShareDefinition{
        Id:              share.ID,
        Name:            share.Name,
        Host:            &protocol.Reference{Name: hostName},
        Path:            share.Path,
        Type:            "nfs",
        OptionsAsString: share.ShareOptions,
    }
}

// ShareMountFromPropertyToProtocol convert share mount on host to protocol message
func ShareMountFromPropertyToProtocol(shareName string, hostName string, mount *propertiesv1.HostRemoteMount) *protocol.ShareMountDefinition {
    return &protocol.ShareMountDefinition{
        Share: &protocol.Reference{Name: shareName},
        Host:  &protocol.Reference{Name: hostName},
        Path:  mount.Path,
        Type:  mount.FileSystem,
    }
}

// ShareMountListFromPropertyToProtocol converts share mounts from host to protocol message
func ShareMountListFromPropertyToProtocol(hostName string, share *propertiesv1.HostShare, mounts map[string]*propertiesv1.HostRemoteMount) *protocol.ShareMountList {
    var pbMounts []*protocol.ShareMountDefinition
    for k, v := range mounts {
        pbMounts = append(pbMounts, &protocol.ShareMountDefinition{
            Host:  &protocol.Reference{Name: k},
            Share: &protocol.Reference{Name: share.Name},
            Path:  v.Path,
            Type:  "nfs",
        })
    }
    return &protocol.ShareMountList{
        Share:     ShareFromPropertyToProtocol(hostName, share),
        MountList: pbMounts,
    }
}

// // VolumeAttachmentFromPropertyToProtocol converts an api.Volume to a *VolumeInfo
// func VolumeAttachmentFromPropertyToProtocol(hostRef string, va propertiesv1.HostLocalMount) *protocol.VolumeAttachmentResponse {
// 	out := &protocol.VolumeAttachmentResponse{
// 		Host:      &protocol.Reference{GetName: hostRef},
// 		MountPath: va.Path,
// 		Device:    va.Device,
// 		Format:    va.FileSystem,
// 	}
// 	return out
// }

// ClusterControlplaneFromPropertyToProtocol does what the name says
func ClusterControlplaneFromPropertyToProtocol(in propertiesv1.ClusterControlplane) *protocol.ClusterControlplane {
    out := protocol.ClusterControlplane{}
    if in.VirtualIP != nil {
        out.Vip = VirtualIPFromAbstractToProtocol(*in.VirtualIP)
    }
    return &out
}

// ClusterCompositeFromPropertyTo Protocol does what the name says
func ClusterCompositeFromPropertyToProtocol(in propertiesv1.ClusterComposite) *protocol.ClusterComposite {
    out := protocol.ClusterComposite{}
    out.Tenants = make([]string, len(in.Tenants))
    copy(out.Tenants, in.Tenants)
    return &out
}
