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

package ovh

// // CreateVolume creates a block volume
// // - name is the name of the volume
// // - size is the size of the volume in GB
// // - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
// func (client *Client) CreateVolume(request api.VolumeRequest) (*api.Volume, error) {
// 	return client.osclt.CreateVolume(request)
// }

// // GetVolume returns the volume identified by id
// func (client *Client) GetVolume(id string) (*api.Volume, error) {
// 	return client.osclt.GetVolume(id)
// }

// //ListVolumes return the list of all volume known on the current tenant (all=ture)
// //or 'only' thode monitored by safescale (all=false) ie those monitored by metadata
// func (client *Client) ListVolumes(all bool) ([]api.Volume, error) {
// 	return client.osclt.ListVolumes(all)
// }

// // DeleteVolume deletes the volume identified by id
// func (client *Client) DeleteVolume(id string) error {
// 	return client.osclt.DeleteVolume(id)
// }

// // CreateVolumeAttachment attaches a volume to an host
// // - 'name' of the volume attachment
// // - 'volume' to attach
// // - 'host' on which the volume is attached
// func (client *Client) CreateVolumeAttachment(request api.VolumeAttachmentRequest) (*api.VolumeAttachment, error) {
// 	return client.osclt.CreateVolumeAttachment(request)
// }

// // GetVolumeAttachment returns the volume attachment identified by id
// func (client *Client) GetVolumeAttachment(serverID, id string) (*api.VolumeAttachment, error) {
// 	return client.osclt.GetVolumeAttachment(serverID, id)
// }

// // ListVolumeAttachments lists available volume attachment
// func (client *Client) ListVolumeAttachments(serverID string) ([]api.VolumeAttachment, error) {
// 	return client.osclt.ListVolumeAttachments(serverID)
// }

// // DeleteVolumeAttachment deletes the volume attachment identifed by id
// func (client *Client) DeleteVolumeAttachment(serverID, id string) error {
// 	return client.osclt.DeleteVolumeAttachment(serverID, id)
// }

// // CreateContainer creates an object container
// func (client *Client) CreateContainer(name string) error {
// 	return client.osclt.CreateContainer(name)
// }

// // DeleteContainer deletes an object container
// func (client *Client) DeleteContainer(name string) error {
// 	return client.osclt.DeleteContainer(name)
// }

// // UpdateContainer updates an object container
// func (client *Client) UpdateContainer(name string, meta map[string]string) error {
// 	return client.osclt.UpdateContainer(name, meta)
// }

// // GetContainerMetadata get an object container metadata
// func (client *Client) GetContainerMetadata(name string) (map[string]string, error) {
// 	return client.osclt.GetContainerMetadata(name)
// }

// // GetContainer get container info
// func (client *Client) GetContainer(name string) (*api.ContainerInfo, error) {
// 	return client.osclt.GetContainer(name)
// }

// // ListContainers list object containers
// func (client *Client) ListContainers() ([]string, error) {
// 	return client.osclt.ListContainers()
// }

// // PutObject put an object into an object container
// func (client *Client) PutObject(container string, obj api.Object) error {
// 	return client.osclt.PutObject(container, obj)
// }

// // UpdateObjectMetadata update an object into an object container
// func (client *Client) UpdateObjectMetadata(container string, obj api.Object) error {
// 	return client.osclt.UpdateObjectMetadata(container, obj)
// }

// // GetObject get  object content from an object container
// func (client *Client) GetObject(container string, name string, ranges []api.Range) (*api.Object, error) {
// 	return client.osclt.GetObject(container, name, ranges)
// }

// // GetObjectMetadata get  object metadata from an object container
// func (client *Client) GetObjectMetadata(container string, name string) (*api.Object, error) {
// 	return client.osclt.GetObjectMetadata(container, name)
// }

// // ListObjects list objects of a container
// func (client *Client) ListObjects(container string, filter api.ObjectFilter) ([]string, error) {
// 	return client.osclt.ListObjects(container, filter)
// }

// // CopyObject copies an object
// func (client *Client) CopyObject(containerSrc, objectSrc, objectDst string) error {
// 	return client.osclt.CopyObject(containerSrc, objectSrc, objectDst)
// }

// // DeleteObject deleta an object from a container
// func (client *Client) DeleteObject(container, object string) error {
// 	return client.osclt.DeleteObject(container, object)
// }
