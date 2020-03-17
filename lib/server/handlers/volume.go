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

package handlers

import (
	"fmt"
	"reflect"
	"strings"

	mapset "github.com/deckarep/golang-set"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumeproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	volumefactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/volume"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system/nfs"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

//go:generate mockgen -destination=../mocks/mock_volumeapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers VolumeHandler

// VolumeHandler defines API to manipulate hosts
type VolumeHandler interface {
	Delete(ref string) error
	List(all bool) ([]resources.Volume, error)
	Inspect(ref string) (resources.Volume, error)
	Create(name string, size int, speed volumespeed.Enum) (resources.Volume, error)
	Attach(volume string, host string, path string, format string, doNotFormat bool) error
	Detach(volume string, host string) error
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
func (handler *volumeHandler) List(all bool) (volumes []resources.Volume, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.volume"), "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objv, err := volumefactory.New(handler.job.SafeGetService())
	if err != nil {
		return nil, err
	}
	err = objv.Browse(task, func(volume *abstract.Volume) error {
		rv, innerErr := volumefactory.Load(task, handler.job.SafeGetService(), volume.ID)
		if innerErr != nil {
			return innerErr
		}
		volumes = append(volumes, rv)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return volumes, nil
}

// Delete deletes volume referenced by ref
func (handler *volumeHandler) Delete(ref string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.volume"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	objv, err := volumefactory.Load(task, handler.job.SafeGetService(), ref)
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound:
			return abstract.ResourceNotFoundError("volume", ref)
		default:
			logrus.Debugf("failed to delete volume: %+v", err)
			return err
		}
	}

	err = objv.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(volumeproperty.AttachedV1, func(clonable data.Clonable) error {
			volumeAttachmentsV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			nbAttach := uint(len(volumeAttachmentsV1.Hosts))
			if nbAttach > 0 {
				var list []string
				for _, v := range volumeAttachmentsV1.Hosts {
					list = append(list, v)
				}
				return scerr.InvalidRequestError("still attached to %d host%s: %s", nbAttach, strprocess.Plural(nbAttach), strings.Join(list, ", "))
			}
			return nil
		})
	})
	if err != nil {
		return err
	}

	err = objv.Delete(task)
	if err != nil {
		return err
	}

	return nil
}

// Inspect returns the volume identified by ref and its attachment (if any)
func (handler *volumeHandler) Inspect(ref string) (volume resources.Volume, err error) {

	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be empty!")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.volume"), "('"+ref+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	objv, err := volumefactory.Load(task, handler.job.SafeGetService(), ref)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return nil, abstract.ResourceNotFoundError("volume", ref)
		}
		return nil, err
	}
	return objv, nil
	// volumeID := objv.SafeGetID()

	// mounts = map[string]*propertiesv1.HostLocalMount{}
	// err = objv.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
	// 	return props.Inspect(volumeproperty.AttachedV1, func(clonable data.Clonable) error {
	// 		volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
	// 		if !ok {
	// 			return scerr.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	// 		if len(volumeAttachedV1.Hosts) > 0 {
	// 			for id := range volumeAttachedV1.Hosts {
	// 				host, inErr := hostfactory.Load(task, handler.job.SafeGetService(), id)
	// 				if inErr != nil {
	// 					logrus.Debug(inErr.Error())
	// 					continue
	// 				}
	// 				inErr = host.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
	// 					return props.Inspect(hostproperty.VolumesV1, func(clonable data.Clonable) error {
	// 						hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
	// 						if !ok {
	// 							return scerr.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 						}
	// 						if volumeAttachment, found := hostVolumesV1.VolumesByID[volumeID]; found {
	// 							return props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) error {
	// 								hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
	// 								if !ok {
	// 									return scerr.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 								}
	// 								if mount, ok := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[volumeAttachment.Device]]; ok {
	// 									mounts[host.SafeGetName()] = mount
	// 								} else {
	// 									mounts[host.SafeGetName()] = propertiesv1.NewHostLocalMount()
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
func (handler *volumeHandler) Create(name string, size int, speed volumespeed.Enum) (objv resources.Volume, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty!")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.volume"), "('%s', %d, %s)", name, size, speed.String()).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objv, err = volumefactory.New(handler.job.SafeGetService())
	if err != nil {
		return nil, err
	}
	request := abstract.VolumeRequest{
		Name:  name,
		Size:  size,
		Speed: speed,
	}
	err = objv.Create(task, request)
	if err != nil {
		return nil, err
	}
	return objv, nil
}

// Attach a volume to an host
func (handler *volumeHandler) Attach(volumeRef, hostRef, path, format string, doNotFormat bool) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if volumeRef == "" {
		return scerr.InvalidParameterError("volumeRef", "cannot be empty string")
	}
	if hostRef == "" {
		return scerr.InvalidParameterError("hostRef", "cannot be empty string")
	}
	if path == "" {
		return scerr.InvalidParameterError("path", "cannot be empty string")
	}
	if format == "" {
		return scerr.InvalidParameterError("format", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.volume"), "('%s', '%s', '%s', '%s', %v)", volumeRef, hostRef, path, format, doNotFormat)
	defer tracer.WithStopwatch().Entering().OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	// Get volume data
	objv, err := handler.Inspect(volumeRef)
	if err != nil {
		return err
	}
	volumeName := objv.SafeGetName()
	volumeID := objv.SafeGetID()

	// Get Host data
	host, err := hostfactory.Load(task, handler.job.SafeGetService(), hostRef)
	if err != nil {
		return err
	}
	hostName := host.SafeGetName()
	hostID := host.SafeGetID()

	var (
		deviceName string
		volumeUUID string
		mountPoint string
		// vaID       string
		server *nfs.Server
	)

	err = objv.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(volumeproperty.AttachedV1, func(clonable data.Clonable) error {
			volumeAttachedV1 := clonable.(*propertiesv1.VolumeAttachments)

			mountPoint = path
			if path == abstract.DefaultVolumeMountPoint {
				mountPoint = abstract.DefaultVolumeMountPoint + volumeName
			}

			// For now, allows only one attachment...
			if len(volumeAttachedV1.Hosts) > 0 {
				hostID := host.SafeGetID()
				for id := range volumeAttachedV1.Hosts {
					if id != hostID {
						return abstract.ResourceNotAvailableError("volume", volumeName)
					}
					break
				}
			}

			return host.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
				return props.Alter(hostproperty.VolumesV1, func(clonable data.Clonable) error {
					hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
					if !ok {
						return scerr.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					return props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) error {
						hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
						if !ok {
							return scerr.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						// Check if the volume is already mounted elsewhere
						if device, found := hostVolumesV1.DevicesByID[objv.SafeGetID()]; found {
							mount, ok := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[device]]
							if !ok {
								return scerr.InconsistentError("metadata inconsistency for volume '%s' attached to host '%s'", volumeName, hostName)
							}
							path := mount.Path
							if path != mountPoint {
								return scerr.DuplicateError("volume '%s' is already attached in '%s:%s'", volumeName, hostName, path)
							}
							return nil
						}

						// Check if there is no other device mounted in the path (or in subpath)
						for _, i := range hostMountsV1.LocalMountsByPath {
							if strings.Index(i.Path, mountPoint) == 0 {
								return scerr.InvalidRequestError("cannot attach volume '%s' to '%s:%s': there is already a volume mounted in '%s:%s'", volumeName, hostName, mountPoint, hostName, i.Path)
							}
						}
						for _, i := range hostMountsV1.RemoteMountsByPath {
							if strings.Index(i.Path, mountPoint) == 0 {
								return scerr.InvalidRequestError("cannot attach volume '%s' to '%s:%s': there is a share mounted in path '%s:%s[/...]'", volumeName, hostName, mountPoint, hostName, i.Path)
							}
						}

						// Note: most providers are not able to tell the real device name the volume
						//       will have on the host, so we have to use a way that can work everywhere
						// Get list of disks before attachment
						oldDiskSet, err := handler.listAttachedDevices(host)
						if err != nil {
							return err
						}
						vaID, err := handler.job.SafeGetService().CreateVolumeAttachment(abstract.VolumeAttachmentRequest{
							Name:     fmt.Sprintf("%s-%s", volumeName, hostName),
							HostID:   host.SafeGetID(),
							VolumeID: objv.SafeGetID(),
						})
						if err != nil {
							switch err.(type) {
							case scerr.ErrNotFound, scerr.ErrInvalidRequest, scerr.ErrTimeout:
								return err
							default:
								return err
							}
						}
						// Starting from here, remove volume attachment if exit with error
						defer func() {
							if err != nil {
								derr := handler.job.SafeGetService().DeleteVolumeAttachment(hostID, vaID)
								if derr != nil {
									switch derr.(type) {
									case scerr.ErrNotFound:
										logrus.Errorf("Cleaning up on failure, failed to detach volume '%s' from host '%s': %v", volumeName, hostName, derr)
									case scerr.ErrTimeout:
										logrus.Errorf("Cleaning up on failure, failed to detach volume '%s' from host '%s': %v", volumeName, hostName, derr)
									default:
										logrus.Errorf("Cleaning up on failure, failed to detach volume '%s' from host '%s': %v", volumeName, hostName, derr)
									}
									err = scerr.AddConsequence(err, derr)
								}
							}
						}()

						// Updates volume properties
						volumeAttachedV1.Hosts[hostID] = hostName

						// Retries to acknowledge the volume is really attached to host
						var newDisk mapset.Set
						retryErr := retry.WhileUnsuccessfulDelay1Second(
							func() error {
								// Get new of disk after attachment
								newDiskSet, err := handler.listAttachedDevices(host)
								if err != nil {
									return err
								}
								// Isolate the new device
								newDisk = newDiskSet.Difference(oldDiskSet)
								if newDisk.Cardinality() == 0 {
									return scerr.NotFoundError("disk not yet attached, retrying")
								}
								return nil
							},
							temporal.GetContextTimeout(),
						)
						if retryErr != nil {
							return scerr.NotFoundError("failed to confirm the disk attachment after %s", temporal.GetContextTimeout())
						}

						// Recovers real device name from the system
						deviceName = "/dev/" + newDisk.ToSlice()[0].(string)

						// Create mount point
						sshHandler := NewSSHHandler(handler.job)
						sshConfig, err := sshHandler.GetConfig(host.SafeGetID())
						if err != nil {
							return err
						}

						server, err = nfs.NewServer(sshConfig)
						if err != nil {
							return err
						}
						volumeUUID, err = server.MountBlockDevice(task, deviceName, mountPoint, format, doNotFormat)
						if err != nil {
							return err
						}

						// Saves volume information in property
						hostVolumesV1.VolumesByID[volumeID] = &propertiesv1.HostVolume{
							AttachID: vaID,
							Device:   volumeUUID,
						}
						hostVolumesV1.VolumesByName[volumeName] = volumeID
						hostVolumesV1.VolumesByDevice[volumeUUID] = volumeID
						hostVolumesV1.DevicesByID[volumeID] = volumeUUID

						// Starting from here, unmount block device if exiting with error
						defer func() {
							if err != nil {
								derr := server.UnmountBlockDevice(task, volumeUUID)
								if derr != nil {
									logrus.Errorf("failed to unmount volume '%s' from host '%s': %v", volumeName, hostName, derr)
									err = scerr.AddConsequence(err, derr)
								}
							}
						}()

						// Updates host properties
						hostMountsV1.LocalMountsByPath[mountPoint] = &propertiesv1.HostLocalMount{
							Device:     volumeUUID,
							Path:       mountPoint,
							FileSystem: "nfs",
						}
						hostMountsV1.LocalMountsByDevice[volumeUUID] = mountPoint

						return nil
					})
				})
			})
		})
	})
	if err != nil {
		return err
	}

	logrus.Infof("Volume '%s' successfully attached to host '%s' as device '%s'", objv.SafeGetName(), host.SafeGetName(), volumeUUID)
	return nil
}

func (handler *volumeHandler) listAttachedDevices(host resources.Host) (set mapset.Set, err error) { // FIXME Make sure ctx is propagated
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if host == nil {
		return nil, scerr.InvalidParameterError("host", "cannot be nil")
	}
	task := handler.job.SafeGetTask()
	defer scerr.OnExitLogError(concurrency.NewTracer(task, debug.IfTrace("handlers.volume"), "").TraceMessage(""), &err)()

	var (
		retcode        int
		stdout, stderr string
	)
	cmd := "sudo lsblk -l -o NAME,TYPE | grep disk | cut -d' ' -f1"
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			retcode, stdout, stderr, err = host.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
			if err != nil {
				return err
			}
			if retcode != 0 {
				if retcode == 255 {
					return scerr.NotAvailableError("failed to reach SSH service of host '%s', retrying", host.SafeGetName())
				}
				return scerr.NewError(stderr)
			}
			return nil
		},
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return nil, scerr.Wrap(retryErr, fmt.Sprintf("failed to get list of connected disks after %s", temporal.GetContextTimeout()))
	}
	disks := strings.Split(stdout, "\n")
	set = mapset.NewThreadUnsafeSet()
	for _, k := range disks {
		set.Add(k)
	}
	return set, nil
}

// Detach detach the volume identified by ref, ref can be the name or the id
func (handler *volumeHandler) Detach(volumeRef, hostRef string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if volumeRef == "" {
		return scerr.InvalidParameterError("volumeRef", "cannot be empty string")
	}
	if hostRef == "" {
		return scerr.InvalidParameterError("hostRef", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.volume"), "('%s', '%s')", volumeRef, hostRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	// Load volume data
	objv, err := volumefactory.Load(task, handler.job.SafeGetService(), volumeRef)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return err
		}
		return abstract.ResourceNotFoundError("volume", volumeRef)
	}
	mountPath := ""

	// Load host data
	host, err := hostfactory.Load(task, handler.job.SafeGetService(), hostRef)
	if err != nil {
		return err
	}

	hostName := host.SafeGetName()
	hostID := host.SafeGetID()
	volumeName := objv.SafeGetName()
	volumeID := objv.SafeGetID()

	// Obtain volume attachment ID
	err = host.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(hostproperty.VolumesV1, func(clonable data.Clonable) error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return scerr.InconsistentError("'*props.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// Check the volume is effectively attached
			attachment, found := hostVolumesV1.VolumesByID[volumeID]
			if !found {
				return scerr.NotFoundError("cannot detach volume '%s': not attached to host '%s'", volumeName, host.SafeGetName())
			}

			// Obtain mounts information
			return props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) error {
				hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
				if !ok {
					return scerr.InconsistentError("'*props.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				device := attachment.Device
				mountPath = hostMountsV1.LocalMountsByDevice[device]
				mount := hostMountsV1.LocalMountsByPath[mountPath]
				if mount == nil {
					return scerr.InconsistentError("metadata inconsistency: no mount corresponding to volume attachment")
				}

				// Check if volume has other mount(s) inside it
				for p, i := range hostMountsV1.LocalMountsByPath {
					if i.Device == device {
						continue
					}
					if strings.Index(p, mount.Path) == 0 {
						return scerr.InvalidRequestError("cannot detach volume '%s' from '%s:%s', there is a volume mounted in '%s:%s'",
							volumeName, hostName, mount.Path, hostName, p)
					}
				}
				for p := range hostMountsV1.RemoteMountsByPath {
					if strings.Index(p, mount.Path) == 0 {
						return scerr.InvalidRequestError("cannot detach volume '%s' from '%s:%s', there is a share mounted in '%s:%s'",
							volumeName, hostName, mount.Path, hostName, p)
					}
				}

				// Check if volume (or a subdir in volume) is shared
				return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) error {
					hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
					if !ok {
						return scerr.InconsistentError("'*props.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					for _, v := range hostSharesV1.ByID {
						if strings.Index(v.Path, mount.Path) == 0 {
							return scerr.InvalidRequestError("cannot detach volume '%s' from '%s:%s', '%s:%s' is shared",
								volumeName, hostName, mount.Path, hostName, v.Path)
						}
					}

					// Unmount the Block Device ...
					sshConfig, err := host.GetSSHConfig(task)
					if err != nil {
						return err
					}
					nfsServer, err := nfs.NewServer(sshConfig)
					if err != nil {
						return err
					}
					err = nfsServer.UnmountBlockDevice(task, attachment.Device)
					if err != nil {
						// FIXME Think about this
						logrus.Error(err)
						//return err
					}

					// ... then detach volume
					err = handler.job.SafeGetService().DeleteVolumeAttachment(hostID, attachment.AttachID)
					if err != nil {
						return err
					}

					// Updates host property propertiesv1.VolumesV1
					delete(hostVolumesV1.VolumesByID, volumeID)
					delete(hostVolumesV1.VolumesByName, volumeName)
					delete(hostVolumesV1.VolumesByDevice, attachment.Device)
					delete(hostVolumesV1.DevicesByID, volumeID)

					// Updates host property propertiesv1.MountsV1
					delete(hostMountsV1.LocalMountsByDevice, mount.Device)
					delete(hostMountsV1.LocalMountsByPath, mount.Path)

					// Updates volume property propertiesv1.VolumeAttachments
					return objv.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
						return props.Alter(volumeproperty.AttachedV1, func(clonable data.Clonable) error {
							volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
							if !ok {
								return scerr.InconsistentError("'*props.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
							}
							delete(volumeAttachedV1.Hosts, hostID)
							return nil
						})
					})
				})
			})
		})
	})
	if err != nil {
		return err
	}

	return nil
}
