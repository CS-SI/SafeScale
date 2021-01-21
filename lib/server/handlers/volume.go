/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumeproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	volumefactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/volume"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
)

//go:generate mockgen -destination=../mocks/mock_volumeapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers VolumeHandler

// VolumeHandler defines API to manipulate hosts
type VolumeHandler interface {
	Delete(ref string) fail.Error
	List(all bool) ([]resources.Volume, fail.Error)
	Inspect(ref string) (resources.Volume, fail.Error)
	Create(name string, size int, speed volumespeed.Enum) (resources.Volume, fail.Error)
	Attach(volume string, host string, path string, format string, doNotFormat bool) fail.Error
	Detach(volume string, host string) fail.Error
}

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// FIXME ROBUSTNESS All functions MUST propagate context

// volumeHandler volume service
type volumeHandler struct {
	job server.Job
}

// NewVolumeHandler creates a Volume service
func NewVolumeHandler(job server.Job) VolumeHandler {
	return &volumeHandler{job: job}
}

// List returns the network list
func (handler *volumeHandler) List(all bool) (volumes []resources.Volume, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.volume"), "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	objv, xerr := volumefactory.New(handler.job.GetService())
	if xerr != nil {
		return nil, xerr
	}
	xerr = objv.Browse(task, func(volume *abstract.Volume) fail.Error {
		rv, innerXErr := volumefactory.Load(task, handler.job.GetService(), volume.ID)
		if innerXErr != nil {
			return innerXErr
		}
		volumes = append(volumes, rv)
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}
	return volumes, nil
}

// Delete deletes volume referenced by ref
func (handler *volumeHandler) Delete(ref string) (xerr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.volume"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	objv, xerr := volumefactory.Load(task, handler.job.GetService(), ref)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return abstract.ResourceNotFoundError("volume", ref)
		default:
			logrus.Debugf("failed to delete volume: %+v", xerr)
			return xerr
		}
	}

	xerr = objv.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
			volumeAttachmentsV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			nbAttach := uint(len(volumeAttachmentsV1.Hosts))
			if nbAttach > 0 {
				var list []string
				for _, v := range volumeAttachmentsV1.Hosts {
					list = append(list, v)
				}
				return fail.InvalidRequestError("still attached to %d host%s: %s", nbAttach, strprocess.Plural(nbAttach), strings.Join(list, ", "))
			}
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	return objv.Delete(task)
}

// Inspect returns the volume identified by ref and its attachment (if any)
func (handler *volumeHandler) Inspect(ref string) (volume resources.Volume, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty!")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.volume"), "('"+ref+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	objv, xerr := volumefactory.Load(task, handler.job.GetService(), ref)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); ok {
			return nil, abstract.ResourceNotFoundError("volume", ref)
		}
		return nil, xerr
	}
	return objv, nil
	// volumeID := objv.GetID()

	// mounts = map[string]*propertiesv1.HostLocalMount{}
	// err = objv.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
	// 	return props.Inspect(volumeproperty.AttachedV1, func(clonable data.Clonable) error {
	// 		volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
	// 		if !ok {
	// 			return fail.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	// 		if len(volumeAttachedV1.Hosts) > 0 {
	// 			for id := range volumeAttachedV1.Hosts {
	// 				host, inErr := hostfactory.Load(task, handler.job.GetService(), id)
	// 				if inErr != nil {
	// 					logrus.Debug(inErr.Error())
	// 					continue
	// 				}
	// 				inErr = host.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
	// 					return props.Inspect(hostproperty.VolumesV1, func(clonable data.Clonable) error {
	// 						hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
	// 						if !ok {
	// 							return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 						}
	// 						if volumeAttachment, found := hostVolumesV1.VolumesByID[volumeID]; found {
	// 							return props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) error {
	// 								hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
	// 								if !ok {
	// 									return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 								}
	// 								if mount, ok := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[volumeAttachment.Device]]; ok {
	// 									mounts[host.GetName()] = mount
	// 								} else {
	// 									mounts[host.GetName()] = propertiesv1.NewHostLocalMount()
	// 								}
	// 								return nil
	// 							})
	// 						}
	// 						return nil
	// 					})
	// 				})
	// 				if inErr != nil {
	// 					logrus.Debug(inErr.Error())
	// 					continue
	// 				}
	// 			}
	// 		}
	// 		return nil
	// 	})
	// })
	// if err != nil {
	// 	return nil, nil, err
	// }
	// return objv, mounts, nil
}

// Create a volume
func (handler *volumeHandler) Create(name string, size int, speed volumespeed.Enum) (objv resources.Volume, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty!")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.volume"), "('%s', %d, %s)", name, size, speed.String()).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	objv, xerr = volumefactory.New(handler.job.GetService())
	if xerr != nil {
		return nil, xerr
	}
	request := abstract.VolumeRequest{
		Name:  name,
		Size:  size,
		Speed: speed,
	}
	if xerr = objv.Create(task, request); xerr != nil {
		return nil, xerr
	}
	return objv, nil
}

// Attach a volume to an host
func (handler *volumeHandler) Attach(volumeRef, hostRef, path, format string, doNotFormat bool) (xerr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if volumeRef == "" {
		return fail.InvalidParameterError("volumeRef", "cannot be empty string")
	}
	if hostRef == "" {
		return fail.InvalidParameterError("hostRef", "cannot be empty string")
	}
	if path == "" {
		return fail.InvalidParameterError("path", "cannot be empty string")
	}
	if format == "" {
		return fail.InvalidParameterError("format", "cannot be empty string")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.volume"), "('%s', '%s', '%s', '%s', %v)", volumeRef, hostRef, path, format, doNotFormat)
	defer tracer.WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	svc := handler.job.GetService()
	rv, xerr := volumefactory.Load(task, svc, volumeRef)
	if xerr != nil {
		return xerr
	}

	rh, xerr := hostfactory.Load(task, svc, hostRef)
	if xerr != nil {
		return xerr
	}

	return rv.Attach(task, rh, path, format, doNotFormat)
	//
	// // Get volume data
	// rv, xerr := handler.Inspect(volumeRef)
	// if xerr != nil {
	// 	return xerr
	// }
	// volumeName := rv.GetName()
	// volumeID := rv.GetID()
	//
	// // Get IPAddress data
	// rh, xerr := hostfactory.Load(task, handler.job.GetService(), hostRef)
	// if xerr != nil {
	// 	return xerr
	// }
	// hostName := rh.GetName()
	// hostID := rh.GetID()
	//
	// var (
	// 	deviceName string
	// 	volumeUUID string
	// 	mountPoint string
	// 	// vaID       string
	// 	server *nfs.getServer
	// )
	//
	// xerr = rv.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
	// 	return props.Alter(task, volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
	// 		volumeAttachedV1 := clonable.(*propertiesv1.VolumeAttachments)
	//
	// 		mountPoint = path
	// 		if path == abstract.DefaultVolumeMountPoint {
	// 			mountPoint = abstract.DefaultVolumeMountPoint + volumeName
	// 		}
	//
	// 		// For now, allows only one attachment...
	// 		if len(volumeAttachedV1.Hosts) > 0 {
	// 			hostID := rh.GetID()
	// 			for id := range volumeAttachedV1.Hosts {
	// 				if id != hostID {
	// 					return abstract.ResourceNotAvailableError("volume", volumeName)
	// 				}
	// 				break
	// 			}
	// 		}
	//
	// 		return rh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
	// 			return props.Alter(task, hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
	// 				hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
	// 				if !ok {
	// 					return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 				}
	// 				return props.Alter(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
	// 					hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
	// 					if !ok {
	// 						return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 					}
	// 					// Check if the volume is already mounted elsewhere
	// 					if device, found := hostVolumesV1.DevicesByID[rv.GetID()]; found {
	// 						mount, ok := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[device]]
	// 						if !ok {
	// 							return fail.InconsistentError("metadata inconsistency for volume '%s' attached to rh '%s'", volumeName, hostName)
	// 						}
	// 						path := mount.Path
	// 						if path != mountPoint {
	// 							return fail.DuplicateError("volume '%s' is already attached in '%s:%s'", volumeName, hostName, path)
	// 						}
	// 						return nil
	// 					}
	//
	// 					// Check if there is no other device mounted in the path (or in subpath)
	// 					for _, i := range hostMountsV1.LocalMountsByPath {
	// 						if strings.Index(i.Path, mountPoint) == 0 {
	// 							return fail.InvalidRequestError("cannot attach volume '%s' to '%s:%s': there is already a volume mounted in '%s:%s'", volumeName, hostName, mountPoint, hostName, i.Path)
	// 						}
	// 					}
	// 					for _, i := range hostMountsV1.RemoteMountsByPath {
	// 						if strings.Index(i.Path, mountPoint) == 0 {
	// 							return fail.InvalidRequestError("cannot attach volume '%s' to '%s:%s': there is a share mounted in path '%s:%s[/...]'", volumeName, hostName, mountPoint, hostName, i.Path)
	// 						}
	// 					}
	//
	// 					// Note: most providers are not able to tell the real device name the volume
	// 					//       will have on the rh, so we have to use a way that can work everywhere
	// 					// Get list of disks before attachment
	// 					oldDiskSet, innerXErr := handler.listAttachedDevices(rh)
	// 					if innerXErr != nil {
	// 						return innerXErr
	// 					}
	// 					vaID, innerXErr := handler.job.GetService().CreateVolumeAttachment(abstract.VolumeAttachmentRequest{
	// 						GetName:     fmt.Sprintf("%s-%s", volumeName, hostName),
	// 						HostID:   rh.GetID(),
	// 						VolumeID: rv.GetID(),
	// 					})
	// 					if innerXErr != nil {
	// 						return innerXErr
	// 					}
	//
	// 					// Starting from here, remove volume attachment if exit with error
	// 					defer func() {
	// 						if innerXErr != nil {
	// 							derr := handler.job.GetService().DeleteVolumeAttachment(hostID, vaID)
	// 							if derr != nil {
	// 								switch derr.(type) {
	// 								case fail.ErrNotFound:
	// 									logrus.Errorf("Cleaning up on failure, failed to detach volume '%s' from rh '%s': %v", volumeName, hostName, derr)
	// 								case fail.ErrTimeout:
	// 									logrus.Errorf("Cleaning up on failure, failed to detach volume '%s' from rh '%s': %v", volumeName, hostName, derr)
	// 								default:
	// 									logrus.Errorf("Cleaning up on failure, failed to detach volume '%s' from rh '%s': %v", volumeName, hostName, derr)
	// 								}
	// 								_ = innerXErr.AddConsequence(derr)
	// 							}
	// 						}
	// 					}()
	//
	// 					// Updates volume properties
	// 					volumeAttachedV1.Hosts[hostID] = hostName
	//
	// 					// Retries to acknowledge the volume is really attached to rh
	// 					var newDisk mapset.Set
	// 					retryErr := retry.WhileUnsuccessfulDelay1Second(
	// 						func() error {
	// 							// Get new of disk after attachment
	// 							newDiskSet, innerXErr := handler.listAttachedDevices(rh)
	// 							if innerXErr != nil {
	// 								return innerXErr
	// 							}
	// 							// Isolate the new device
	// 							newDisk = newDiskSet.Difference(oldDiskSet)
	// 							if newDisk.Cardinality() == 0 {
	// 								return fail.NotFoundError("disk not yet attached, retrying")
	// 							}
	// 							return nil
	// 						},
	// 						temporal.GetContextTimeout(),
	// 					)
	// 					if retryErr != nil {
	// 						return fail.NotFoundError("failed to confirm the disk attachment after %s", temporal.GetContextTimeout())
	// 					}
	//
	// 					// Recovers real device name from the system
	// 					deviceName = "/dev/" + newDisk.ToSlice()[0].(string)
	//
	// 					// Create mount point
	// 					sshHandler := NewSSHHandler(handler.job)
	// 					sshConfig, innerXErr := sshHandler.GetConfig(rh.GetID())
	// 					if innerXErr != nil {
	// 						return innerXErr
	// 					}
	//
	// 					if server, innerXErr = nfs.NewServer(sshConfig); innerXErr != nil {
	// 						return innerXErr
	// 					}
	// 					if volumeUUID, innerXErr = server.MountBlockDevice(task, deviceName, mountPoint, format, doNotFormat); innerXErr != nil {
	// 						return innerXErr
	// 					}
	//
	// 					// Saves volume information in property
	// 					hostVolumesV1.VolumesByID[volumeID] = &propertiesv1.HostVolume{
	// 						AttachID: vaID,
	// 						Device:   volumeUUID,
	// 					}
	// 					hostVolumesV1.VolumesByName[volumeName] = volumeID
	// 					hostVolumesV1.VolumesByDevice[volumeUUID] = volumeID
	// 					hostVolumesV1.DevicesByID[volumeID] = volumeUUID
	//
	// 					// Starting from here, unmount block device if exiting with error
	// 					defer func() {
	// 						if innerXErr != nil {
	// 							derr := server.UnmountBlockDevice(task, volumeUUID)
	// 							if derr != nil {
	// 								logrus.Errorf("failed to unmount volume '%s' from rh '%s': %v", volumeName, hostName, derr)
	// 								_ = innerXErr.AddConsequence(derr)
	// 							}
	// 						}
	// 					}()
	//
	// 					// Updates rh properties
	// 					hostMountsV1.LocalMountsByPath[mountPoint] = &propertiesv1.HostLocalMount{
	// 						Device:     volumeUUID,
	// 						Path:       mountPoint,
	// 						FileSystem: "nfs",
	// 					}
	// 					hostMountsV1.LocalMountsByDevice[volumeUUID] = mountPoint
	//
	// 					return nil
	// 				})
	// 			})
	// 		})
	// 	})
	// })
	// if xerr != nil {
	// 	return xerr
	// }
	//
	// logrus.Infof("Volume '%s' successfully attached to rh '%s' as device '%s'", rv.GetName(), rh.GetName(), volumeUUID)
	// return nil
}

// func (handler *volumeHandler) listAttachedDevices(host resources.IPAddress) (set mapset.Set, xerr fail.Error) { // FIXME Make sure ctx is propagated
// 	if handler == nil {
// 		return nil, fail.InvalidInstanceError()
// 	}
// 	if handler.job == nil {
// 		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
// 	}
// 	if host == nil {
// 		return nil, fail.InvalidParameterError("host", "cannot be nil")
// 	}
// 	task := handler.job.GetTask()
// 	defer fail.OnExitLogError(&xerr, debug.NewTracer(task, debug.ShouldTrace("handlers.volume"), "").TraceMessage())
//
// 	var (
// 		retcode        int
// 		stdout, stderr string
// 	)
// 	cmd := "sudo lsblk -l -o NAME,TYPE | grep disk | cut -d' ' -f1"
// 	retryErr := retry.WhileUnsuccessfulDelay1Second(
// 		func() error {
// 			var innerXErr error
// 			retcode, stdout, stderr, innerXErr = host.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
// 			if innerXErr != nil {
// 				return innerXErr
// 			}
// 			if retcode != 0 {
// 				if retcode == 255 {
// 					return fail.NotAvailableError("failed to reach SSH service of host '%s', retrying", host.GetName())
// 				}
// 				return fail.NewError(stderr)
// 			}
// 			return nil
// 		},
// 		temporal.GetContextTimeout(),
// 	)
// 	if retryErr != nil {
// 		return nil, fail.Wrap(retryErr, fmt.Sprintf("failed to get list of connected disks after %s", temporal.GetContextTimeout()))
// 	}
// 	disks := strings.Split(stdout, "\n")
// 	set = mapset.NewThreadUnsafeSet()
// 	for _, k := range disks {
// 		set.Add(k)
// 	}
// 	return set, nil
// }

// Detach detach the volume identified by ref, ref can be the name or the id
func (handler *volumeHandler) Detach(volumeRef, hostRef string) (xerr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if volumeRef == "" {
		return fail.InvalidParameterError("volumeRef", "cannot be empty string")
	}
	if hostRef == "" {
		return fail.InvalidParameterError("hostRef", "cannot be empty string")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.volume"), "('%s', '%s')", volumeRef, hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	// Load volume data
	rv, xerr := volumefactory.Load(task, handler.job.GetService(), volumeRef)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return xerr
		}
		return abstract.ResourceNotFoundError("volume", volumeRef)
	}
	// mountPath := ""

	// Load rh data
	rh, xerr := hostfactory.Load(task, handler.job.GetService(), hostRef)
	if xerr != nil {
		return xerr
	}

	return rv.Detach(task, rh)
	// hostName := rh.GetName()
	// hostID := rh.GetID()
	// volumeName := rv.GetName()
	// volumeID := rv.GetID()
	//
	// // Obtain volume attachment ID
	// xerr = rh.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
	// 	return props.Alter(task, hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
	// 		hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
	// 		if !ok {
	// 			return fail.InconsistentError("'*props.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	//
	// 		// Check the volume is effectively attached
	// 		attachment, found := hostVolumesV1.VolumesByID[volumeID]
	// 		if !found {
	// 			return fail.NotFoundError("cannot detach volume '%s': not attached to rh '%s'", volumeName, rh.GetName())
	// 		}
	//
	// 		// Obtain mounts information
	// 		return props.Alter(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
	// 			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
	// 			if !ok {
	// 				return fail.InconsistentError("'*props.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 			}
	// 			device := attachment.Device
	// 			mountPath = hostMountsV1.LocalMountsByDevice[device]
	// 			mount := hostMountsV1.LocalMountsByPath[mountPath]
	// 			if mount == nil {
	// 				return fail.InconsistentError("metadata inconsistency: no mount corresponding to volume attachment")
	// 			}
	//
	// 			// Check if volume has other mount(s) inside it
	// 			for p, i := range hostMountsV1.LocalMountsByPath {
	// 				if i.Device == device {
	// 					continue
	// 				}
	// 				if strings.Index(p, mount.Path) == 0 {
	// 					return fail.InvalidRequestError("cannot detach volume '%s' from '%s:%s', there is a volume mounted in '%s:%s'",
	// 						volumeName, hostName, mount.Path, hostName, p)
	// 				}
	// 			}
	// 			for p := range hostMountsV1.RemoteMountsByPath {
	// 				if strings.Index(p, mount.Path) == 0 {
	// 					return fail.InvalidRequestError("cannot detach volume '%s' from '%s:%s', there is a share mounted in '%s:%s'",
	// 						volumeName, hostName, mount.Path, hostName, p)
	// 				}
	// 			}
	//
	// 			// Check if volume (or a subdir in volume) is shared
	// 			return props.Alter(task, hostproperty.SharesV1, func(clonable data.Clonable) error {
	// 				hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
	// 				if !ok {
	// 					return fail.InconsistentError("'*props.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 				}
	// 				for _, v := range hostSharesV1.ByID {
	// 					if strings.Index(v.Path, mount.Path) == 0 {
	// 						return fail.InvalidRequestError("cannot detach volume '%s' from '%s:%s', '%s:%s' is shared",
	// 							volumeName, hostName, mount.Path, hostName, v.Path)
	// 					}
	// 				}
	//
	// 				// Unmount the Block Device ...
	// 				sshConfig, innerXErr := rh.GetSSHConfig(task)
	// 				if innerXErr != nil {
	// 					return innerXErr
	// 				}
	// 				nfsServer, innerXErr := nfs.NewServer(sshConfig)
	// 				if innerXErr != nil {
	// 					return innerXErr
	// 				}
	// 				if innerXErr = nfsServer.UnmountBlockDevice(task, attachment.Device); innerXErr != nil {
	// 					// FIXME: Think about this
	// 					logrus.Error(innerXErr)
	// 					// return innerXErr
	// 				}
	//
	// 				// ... then detach volume
	// 				if innerXErr = handler.job.GetService().DeleteVolumeAttachment(hostID, attachment.AttachID); innerXErr != nil {
	// 					return innerXErr
	// 				}
	//
	// 				// Updates rh property propertiesv1.VolumesV1
	// 				delete(hostVolumesV1.VolumesByID, volumeID)
	// 				delete(hostVolumesV1.VolumesByName, volumeName)
	// 				delete(hostVolumesV1.VolumesByDevice, attachment.Device)
	// 				delete(hostVolumesV1.DevicesByID, volumeID)
	//
	// 				// Updates rh property propertiesv1.MountsV1
	// 				delete(hostMountsV1.LocalMountsByDevice, mount.Device)
	// 				delete(hostMountsV1.LocalMountsByPath, mount.Path)
	//
	// 				// Updates volume property propertiesv1.VolumeAttachments
	// 				return rv.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
	// 					return props.Alter(task, volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
	// 						volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
	// 						if !ok {
	// 							return fail.InconsistentError("'*props.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 						}
	// 						delete(volumeAttachedV1.Hosts, hostID)
	// 						return nil
	// 					})
	// 				})
	// 			})
	// 		})
	// 	})
	// })
	// if xerr != nil {
	// 	return xerr
	// }
	//
	// return nil
}
