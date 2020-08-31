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
    "context"
    "fmt"
    "math"
    "strconv"
    "strings"

    "github.com/CS-SI/SafeScale/lib/utils/debug"

    mapset "github.com/deckarep/golang-set"
    "github.com/sirupsen/logrus"

    "github.com/CS-SI/SafeScale/lib/server/iaas"
    "github.com/CS-SI/SafeScale/lib/server/iaas/resources"
    "github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hostproperty"
    "github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/volumeproperty"
    "github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/volumespeed"
    propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
    "github.com/CS-SI/SafeScale/lib/server/metadata"
    "github.com/CS-SI/SafeScale/lib/system/nfs"
    "github.com/CS-SI/SafeScale/lib/utils"
    "github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
    "github.com/CS-SI/SafeScale/lib/utils/data"
    "github.com/CS-SI/SafeScale/lib/utils/retry"
    "github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
    "github.com/CS-SI/SafeScale/lib/utils/scerr"
    "github.com/CS-SI/SafeScale/lib/utils/temporal"
)

//go:generate mockgen -destination=../mocks/mock_volumeapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers VolumeAPI

// VolumeAPI defines API to manipulate hosts
type VolumeAPI interface {
    Delete(ctx context.Context, ref string) error
    List(ctx context.Context, all bool) ([]resources.Volume, error)
    Inspect(ctx context.Context, ref string) (*resources.Volume, map[string]*propsv1.HostLocalMount, error)
    Create(ctx context.Context, name string, size int, speed volumespeed.Enum) (*resources.Volume, error)
    Attach(ctx context.Context, volume string, host string, path string, format string, doNotFormat bool) (string, error)
    Detach(ctx context.Context, volume string, host string) error
    Expand(ctx context.Context, volume string, host string, increment uint32, incrementType string) error
    Shrink(ctx context.Context, volume string, host string, increment uint32, incrementType string) error
}

// VolumeHandler volume service
type VolumeHandler struct {
    service iaas.Service
}

// NewVolumeHandler creates a Volume service
func NewVolumeHandler(svc iaas.Service) VolumeAPI {
    return &VolumeHandler{
        service: svc,
    }
}

// List returns the network list
func (handler *VolumeHandler) List(ctx context.Context, all bool) (volumes []resources.Volume, err error) {
    if handler == nil {
        return nil, scerr.InvalidInstanceError()
    }
    // FIXME: validate parameters

    tracer := debug.NewTracer(nil, "", true).WithStopwatch().GoingIn()
    defer tracer.OnExitTrace()()
    defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

    if all {
        volumes, err := handler.service.ListVolumes()
        return volumes, err
    }

    mv, err := metadata.NewVolume(handler.service)
    if err != nil {
        return nil, err
    }
    err = mv.Browse(
        func(volume *resources.Volume) error {
            volumes = append(volumes, *volume)
            return nil
        },
    )
    if err != nil {
        return nil, err
    }
    return volumes, nil
}

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// Delete deletes volume referenced by ref
func (handler *VolumeHandler) Delete(ctx context.Context, ref string) (err error) {
    if handler == nil {
        return scerr.InvalidInstanceError()
    }
    // FIXME: validate parameters

    tracer := debug.NewTracer(nil, fmt.Sprintf("(%s)", ref), true).WithStopwatch().GoingIn()
    defer tracer.OnExitTrace()()
    defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

    mv, err := metadata.LoadVolume(handler.service, ref)
    if err != nil {
        switch err.(type) {
        case scerr.ErrNotFound:
            return resources.ResourceNotFoundError("volume", ref)
        default:
            logrus.Debugf("failed to delete volume: %+v", err)
            return err
        }
    }
    volume, err := mv.Get()
    if err != nil {
        return err
    }

    err = volume.Properties.LockForRead(volumeproperty.AttachedV1).ThenUse(
        func(clonable data.Clonable) error {
            volumeAttachmentsV1 := clonable.(*propsv1.VolumeAttachments)
            nbAttach := len(volumeAttachmentsV1.Hosts)
            if nbAttach > 0 {
                var list []string
                for _, v := range volumeAttachmentsV1.Hosts {
                    list = append(list, v)
                }
                return fmt.Errorf("still attached to %d host%s: %s", nbAttach, utils.Plural(nbAttach), strings.Join(list, ", "))
            }
            return nil
        },
    )
    if err != nil {
        return err
    }

    err = handler.service.DeleteVolume(volume.ID)
    if err != nil {
        switch err.(type) {
        case scerr.ErrNotFound:
            logrus.Warnf("Unable to find the volume on provider side, cleaning up metadata")
        case scerr.ErrInvalidRequest, scerr.ErrTimeout:
            return err
        default:
            return err
        }
    }
    err = mv.Delete()
    if err != nil {
        return err
    }

    select {
    case <-ctx.Done():
        logrus.Warnf("Volume deletion cancelled by user")
        volumeBis, err := handler.Create(context.Background(), volume.Name, volume.Size, volume.Speed)
        if err != nil {
            return fmt.Errorf("failed to stop volume deletion")
        }
        buf, err := volumeBis.Serialize()
        if err != nil {
            return fmt.Errorf("failed to recreate deleted volume")
        }
        return fmt.Errorf("deleted volume recreated by safescale : %s", buf)
    default:
    }

    return nil
}

// Inspect returns the volume identified by ref and its attachment (if any)
func (handler *VolumeHandler) Inspect(
    ctx context.Context,
    ref string,
) (volume *resources.Volume, mounts map[string]*propsv1.HostLocalMount, err error) {

    if handler == nil {
        return nil, nil, scerr.InvalidInstanceError()
    }
    // FIXME: validate parameters

    tracer := debug.NewTracer(nil, "('"+ref+"')", true).WithStopwatch().GoingIn()
    defer tracer.OnExitTrace()()
    defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

    mv, err := metadata.LoadVolume(handler.service, ref)
    if err != nil {
        if _, ok := err.(scerr.ErrNotFound); ok {
            return nil, nil, resources.ResourceNotFoundError("volume", ref)
        }
        return nil, nil, err
    }
    volume, err = mv.Get()
    if err != nil {
        return nil, nil, err
    }

    mounts = map[string]*propsv1.HostLocalMount{}
    hostSvc := NewHostHandler(handler.service)

    err = volume.Properties.LockForRead(volumeproperty.AttachedV1).ThenUse(
        func(clonable data.Clonable) error {
            volumeAttachedV1 := clonable.(*propsv1.VolumeAttachments)
            if len(volumeAttachedV1.Hosts) > 0 {
                for id := range volumeAttachedV1.Hosts {
                    host, err := hostSvc.Inspect(ctx, id)
                    if err != nil {
                        continue
                    }
                    err = host.Properties.LockForRead(hostproperty.VolumesV1).ThenUse(
                        func(clonable data.Clonable) error {
                            hostVolumesV1 := clonable.(*propsv1.HostVolumes)
                            if volumeAttachment, found := hostVolumesV1.VolumesByID[volume.ID]; found {
                                err = host.Properties.LockForRead(hostproperty.MountsV1).ThenUse(
                                    func(clonable data.Clonable) error {
                                        hostMountsV1 := clonable.(*propsv1.HostMounts)
                                        if mount, ok := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[volumeAttachment.Device]]; ok {
                                            mounts[host.Name] = mount
                                        } else {
                                            mounts[host.Name] = propsv1.NewHostLocalMount()
                                        }
                                        return nil
                                    },
                                )
                                if err != nil {
                                    return err
                                }
                            }
                            return nil
                        },
                    )
                    if err != nil {
                        continue
                    }
                }
            }
            return nil
        },
    )
    if err != nil {
        return nil, nil, err
    }
    return volume, mounts, nil
}

// Create a volume
func (handler *VolumeHandler) Create(ctx context.Context, name string, size int, speed volumespeed.Enum) (
    volume *resources.Volume, err error,
) {
    if handler == nil {
        return nil, scerr.InvalidInstanceError()
    }
    // FIXME: validate parameters

    tracer := debug.NewTracer(nil, fmt.Sprintf("('%s', %d, %s)", name, size, speed.String()), true).WithStopwatch().GoingIn()
    defer tracer.OnExitTrace()()
    defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

    _, err = metadata.LoadVolume(handler.service, name)
    if err != nil {
        if _, ok := err.(scerr.ErrNotFound); !ok {
            return nil, err
        }
    } else {
        return nil, scerr.DuplicateError(fmt.Sprintf("volume '%s' already exists", name))
    }

    volume, err = handler.service.CreateVolume(
        resources.VolumeRequest{
            Name:  name,
            Size:  size,
            Speed: speed,
        },
    )
    if err != nil {
        switch err.(type) {
        case scerr.ErrNotFound, scerr.ErrInvalidRequest, scerr.ErrTimeout:
            return nil, err
        default:
            return nil, err
        }
    }

    // starting from here delete volume if function ends with failure
    newVolume := volume
    defer func() {
        if err != nil {
            derr := handler.service.DeleteVolume(newVolume.ID)
            if derr != nil {
                switch derr.(type) {
                case scerr.ErrNotFound:
                    logrus.Errorf("Cleaning up on failure, failed to delete volume '%s': %v", newVolume.Name, derr)
                case scerr.ErrTimeout:
                    logrus.Errorf("Cleaning up on failure, failed to delete volume '%s': %v", newVolume.Name, derr)
                default:
                    logrus.Errorf("Cleaning up on failure, failed to delete volume '%s': %v", newVolume.Name, derr)
                }
                err = scerr.AddConsequence(err, derr)
            }
        }
    }()

    md, err := metadata.SaveVolume(handler.service, volume)
    if err != nil {
        logrus.Debugf("Error creating volume: saving volume metadata: %+v", err)
        return nil, err
    }

    // starting from here delete volume if function ends with failure
    defer func() {
        if err != nil {
            derr := md.Delete()
            if derr != nil {
                logrus.Warnf("failed to delete metadata of volume '%s'", newVolume.Name)
                err = scerr.AddConsequence(err, derr)
            }
        }
    }()

    select {
    case <-ctx.Done():
        logrus.Warnf("Volume creation cancelled by user")
        err = fmt.Errorf("volume creation cancelled by user")
        return nil, err
    default:
    }

    return volume, nil
}

func (handler *VolumeHandler) isAlreadyMounted(ctx context.Context, hostName string, volume *resources.Volume) (err error) {
    // Get Host data
    hostSvc := NewHostHandler(handler.service)
    host, err := hostSvc.ForceInspect(ctx, hostName)
    if err != nil {
        return err
    }

    err = host.Properties.LockForRead(hostproperty.VolumesV1).ThenUse(
        func(data data.Clonable) error {
            hostVolumesV1 := data.(*propsv1.HostVolumes)
            // Check if the volume is already mounted elsewhere
            if _, found := hostVolumesV1.DevicesByID[volume.ID]; found {
                return fmt.Errorf("volume '%s' is already attached in '%s'", volume.Name, host.Name)
            }
            return nil
        },
    )
    if err != nil {
        return err
    }

    err = volume.Properties.LockForRead(volumeproperty.AttachedV1).ThenUse(
        func(data data.Clonable) error {
            volumeAttachedV1 := data.(*propsv1.VolumeAttachments)
            if len(volumeAttachedV1.Hosts) > 0 {
                return fmt.Errorf("volume '%s' is already attached", volume.Name)
            }
            return nil
        },
    )
    if err != nil {
        return err
    }

    return nil
}

// Attach a volume to an host
func (handler *VolumeHandler) Attach(ctx context.Context, volumeName, hostName, path, format string, doNotFormat bool) (
    _ string, err error,
) {
    if handler == nil {
        return "", scerr.InvalidInstanceError()
    }
    // FIXME: validate parameters
    tracer := debug.NewTracer(
        nil, fmt.Sprintf("('%s', '%s', '%s', '%s', %v)", volumeName, hostName, path, format, doNotFormat), true,
    )
    defer tracer.WithStopwatch().GoingIn().OnExitTrace()()
    defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

    // Get volume data
    volume, _, err := handler.Inspect(ctx, volumeName)
    if err != nil {
        if _, ok := err.(scerr.ErrNotFound); ok {
            return "", err
        }
        return "", err
    }

    // FIXME Handle volume.Formatted
    if volume.ManagedByLVM {
        if len(volume.PVM) != 0 {
            if volume.Formatted {
                logrus.Debug("This should be managed by LVM and it's already formatted")
            } else {
                logrus.Debug("This should be managed by LVM")
            }
            return "", handler.attachLVM(ctx, volumeName, hostName, path, format, doNotFormat || volume.Formatted)
        }
    }

    // Get Host data
    hostSvc := NewHostHandler(handler.service)
    host, err := hostSvc.ForceInspect(ctx, hostName)
    if err != nil {
        return "", err
    }

    var (
        deviceName string
        volumeUUID string
        mountPoint string
        vaID       string
        server     *nfs.Server
    )

    err = volume.Properties.LockForWrite(volumeproperty.AttachedV1).ThenUse(
        func(clonable data.Clonable) error {
            volumeAttachedV1 := clonable.(*propsv1.VolumeAttachments)

            mountPoint = path
            if path == resources.DefaultVolumeMountPoint {
                mountPoint = resources.DefaultVolumeMountPoint + volume.Name
            }

            // For now, allows only one attachment...
            if len(volumeAttachedV1.Hosts) > 0 {
                for id := range volumeAttachedV1.Hosts {
                    if id != host.ID {
                        return resources.ResourceNotAvailableError("volume", volumeName)
                    }
                    break
                }
            }

            return host.Properties.LockForWrite(hostproperty.VolumesV1).ThenUse(
                func(clonable data.Clonable) error {
                    hostVolumesV1 := clonable.(*propsv1.HostVolumes)
                    return host.Properties.LockForWrite(hostproperty.MountsV1).ThenUse(
                        func(clonable data.Clonable) error {
                            hostMountsV1 := clonable.(*propsv1.HostMounts)
                            // Check if the volume is already mounted elsewhere
                            if device, found := hostVolumesV1.DevicesByID[volume.ID]; found {
                                mount, ok := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[device]]
                                if !ok {
                                    return fmt.Errorf(
                                        "metadata inconsistency for volume '%s' attached to host '%s'", volume.Name, host.Name,
                                    )
                                }
                                path := mount.Path
                                if path != mountPoint {
                                    return fmt.Errorf("volume '%s' is already attached in '%s:%s'", volume.Name, host.Name, path)
                                }
                                return nil
                            }

                            // Check if there is no other device mounted in the path (or in subpath)
                            for _, i := range hostMountsV1.LocalMountsByPath {
                                if strings.Index(i.Path, mountPoint) == 0 {
                                    return fmt.Errorf(
                                        "cannot attach volume '%s' to '%s:%s': there is already a volume mounted in '%s:%s'",
                                        volume.Name, host.Name, mountPoint, host.Name, i.Path,
                                    )
                                }
                            }
                            for _, i := range hostMountsV1.RemoteMountsByPath {
                                if strings.Index(i.Path, mountPoint) == 0 {
                                    return fmt.Errorf(
                                        "cannot attach volume '%s' to '%s:%s': there is a share mounted in path '%s:%s[/...]'",
                                        volume.Name, host.Name, mountPoint, host.Name, i.Path,
                                    )
                                }
                            }

                            // Note: most providers are not able to tell the real device name the volume
                            //       will have on the host, so we have to use a way that can work everywhere
                            // Get list of disks before attachment
                            oldDiskSet, err := handler.listAttachedDevices(ctx, host)
                            if err != nil {
                                return err
                            }
                            vaID, err := handler.service.CreateVolumeAttachment(
                                resources.VolumeAttachmentRequest{
                                    Name:     fmt.Sprintf("%s-%s", volume.Name, host.Name),
                                    HostID:   host.ID,
                                    VolumeID: volume.ID,
                                },
                            )
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
                                    derr := handler.service.DeleteVolumeAttachment(host.ID, vaID)
                                    if derr != nil {
                                        switch derr.(type) {
                                        case scerr.ErrNotFound:
                                            logrus.Errorf(
                                                "Cleaning up on failure, failed to detach volume '%s' from host '%s': %v",
                                                volume.Name, host.Name, derr,
                                            )
                                        case scerr.ErrTimeout:
                                            logrus.Errorf(
                                                "Cleaning up on failure, failed to detach volume '%s' from host '%s': %v",
                                                volume.Name, host.Name, derr,
                                            )
                                        default:
                                            logrus.Errorf(
                                                "Cleaning up on failure, failed to detach volume '%s' from host '%s': %v",
                                                volume.Name, host.Name, derr,
                                            )
                                        }
                                        err = scerr.AddConsequence(err, derr)
                                    }
                                }
                            }()

                            // Updates volume properties
                            volumeAttachedV1.Hosts[host.ID] = host.Name

                            // Retries to acknowledge the volume is really attached to host
                            var newDisk mapset.Set
                            retryErr := retry.WhileUnsuccessfulDelay1Second(
                                func() error {
                                    // Get new of disk after attachment
                                    newDiskSet, err := handler.listAttachedDevices(ctx, host)
                                    if err != nil {
                                        return err
                                    }
                                    // Isolate the new device
                                    newDisk = newDiskSet.Difference(oldDiskSet)
                                    if newDisk.Cardinality() == 0 {
                                        return fmt.Errorf("disk not yet attached, retrying")
                                    }
                                    return nil
                                },
                                temporal.GetExecutionTimeout(),
                            )
                            if retryErr != nil {
                                return fmt.Errorf("failed to confirm the disk attachment after %s", temporal.GetExecutionTimeout())
                            }

                            // Recovers real device name from the system
                            deviceName = "/dev/" + newDisk.ToSlice()[0].(string)

                            // Create mount point
                            sshHandler := NewSSHHandler(handler.service)
                            sshConfig, err := sshHandler.GetConfig(ctx, host.ID)
                            if err != nil {
                                return err
                            }

                            server, err = nfs.NewServer(sshConfig)
                            if err != nil {
                                return err
                            }
                            volumeUUID, err = server.MountBlockDevice(deviceName, mountPoint, format, doNotFormat)
                            if err != nil {
                                return err
                            }

                            // Saves volume information in property
                            hostVolumesV1.VolumesByID[volume.ID] = &propsv1.HostVolume{
                                AttachID: vaID,
                                Device:   volumeUUID,
                            }
                            hostVolumesV1.VolumesByName[volume.Name] = volume.ID
                            hostVolumesV1.VolumesByDevice[volumeUUID] = volume.ID
                            hostVolumesV1.DevicesByID[volume.ID] = volumeUUID

                            // Starting from here, unmount block device if exiting with error
                            defer func() {
                                if err != nil {
                                    derr := server.UnmountBlockDevice(volumeUUID)
                                    if derr != nil {
                                        logrus.Errorf(
                                            "failed to unmount volume '%s' from host '%s': %v", volume.Name, host.Name, derr,
                                        )
                                        err = scerr.AddConsequence(err, derr)
                                    }
                                }
                            }()

                            // Updates host properties
                            hostMountsV1.LocalMountsByPath[mountPoint] = &propsv1.HostLocalMount{
                                Device:     volumeUUID,
                                Path:       mountPoint,
                                FileSystem: "nfs",
                            }
                            hostMountsV1.LocalMountsByDevice[volumeUUID] = mountPoint

                            return nil
                        },
                    )
                },
            )
        },
    )
    if err != nil {
        return "", err
    }

    defer func() {
        if err != nil {
            derr := server.UnmountBlockDevice(volumeUUID)
            if derr != nil {
                logrus.Errorf("failed to unmount volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
                err = scerr.AddConsequence(err, derr)
            }
            derr = handler.service.DeleteVolumeAttachment(host.ID, vaID)
            if derr != nil {
                switch derr.(type) {
                case scerr.ErrNotFound:
                    logrus.Errorf(
                        "Cleaning up on failure, failed to detach volume '%s' from host '%s': %v", volume.Name, host.Name, derr,
                    )
                case scerr.ErrTimeout:
                    logrus.Errorf(
                        "Cleaning up on failure, failed to detach volume '%s' from host '%s': %v", volume.Name, host.Name, derr,
                    )
                default:
                    logrus.Errorf(
                        "Cleaning up on failure, failed to detach volume '%s' from host '%s': %v", volume.Name, host.Name, derr,
                    )
                }
                err = scerr.AddConsequence(err, derr)
            }
        }
    }()

    _, err = metadata.SaveVolume(handler.service, volume)
    if err != nil {
        return "", err
    }

    defer func() {
        if err != nil {
            err2 := volume.Properties.LockForWrite(volumeproperty.AttachedV1).ThenUse(
                func(clonable data.Clonable) error {
                    volumeAttachedV1 := clonable.(*propsv1.VolumeAttachments)
                    delete(volumeAttachedV1.Hosts, host.ID)
                    return nil
                },
            )
            if err2 != nil {
                logrus.Warnf("failed to set volume %s metadatas", volumeName)
                err = scerr.AddConsequence(err, err2)
            }
            _, err2 = metadata.SaveVolume(handler.service, volume)
            if err2 != nil {
                logrus.Warnf("failed to save volume %s metadatas", volumeName)
                err = scerr.AddConsequence(err, err2)
            }
        }
    }()

    mh, err := metadata.SaveHost(handler.service, host)
    if err != nil {
        return "", err
    }

    defer func() {
        if err != nil {
            err2 := host.Properties.LockForWrite(hostproperty.VolumesV1).ThenUse(
                func(clonable data.Clonable) error {
                    hostVolumesV1 := clonable.(*propsv1.HostVolumes)
                    delete(hostVolumesV1.VolumesByID, volume.ID)
                    delete(hostVolumesV1.VolumesByName, volume.Name)
                    delete(hostVolumesV1.VolumesByDevice, volumeUUID)
                    delete(hostVolumesV1.DevicesByID, volume.ID)
                    return nil
                },
            )
            if err2 != nil {
                logrus.Warnf("failed to set host '%s' metadata about volumes", volumeName)
                err = scerr.AddConsequence(err, err2)
            }
            err2 = host.Properties.LockForWrite(hostproperty.MountsV1).ThenUse(
                func(clonable data.Clonable) error {
                    hostMountsV1 := clonable.(*propsv1.HostMounts)
                    delete(hostMountsV1.LocalMountsByDevice, volumeUUID)
                    delete(hostMountsV1.LocalMountsByPath, mountPoint)
                    return nil
                },
            )
            if err2 != nil {
                logrus.Warnf("failed to set host '%s' metadata about mounts", volumeName)
                err = scerr.AddConsequence(err, err2)

            }
            err2 = mh.Write()
            if err2 != nil {
                logrus.Warnf("failed to save host '%s' metadata", volumeName)
                err = scerr.AddConsequence(err, err2)
            }
        }
    }()

    select {
    case <-ctx.Done():
        logrus.Warnf("Volume attachment cancelled by user")
        err = fmt.Errorf("volume attachment cancelled by user")
        return "", err
    default:
    }

    logrus.Infof("Volume '%s' successfully attached to host '%s' as device '%s'", volume.Name, host.Name, volumeUUID)
    return deviceName, nil
}

func getHost(ctx context.Context, svc *VolumeHandler, hostName string) (*resources.Host, error) {
    // Load host data
    hostSvc := NewHostHandler(svc.service)
    host, err := hostSvc.ForceInspect(ctx, hostName)
    if err != nil {
        return nil, err
    }

    return host, nil
}

func getHostVolume(ctx context.Context, svc *VolumeHandler, hostName string) (*propsv1.HostVolumes, error) {
    // Load host data
    hostSvc := NewHostHandler(svc.service)
    host, err := hostSvc.ForceInspect(ctx, hostName)
    if err != nil {
        return nil, err
    }

    // Obtain volume attachment ID
    var hostVolumesV1 *propsv1.HostVolumes
    err = host.Properties.LockForRead(hostproperty.VolumesV1).ThenUse(
        func(data data.Clonable) error {
            hostVolumesV1 = data.(*propsv1.HostVolumes)
            return nil
        },
    )
    if err != nil {
        return nil, err
    }

    return hostVolumesV1, nil
}

func (handler *VolumeHandler) attachLVM(
    ctx context.Context, volumeName, hostName, path, format string, doNotFormat bool,
) (err error) {
    // Get volume data
    volume, _, err := handler.Inspect(ctx, volumeName)
    if err != nil {
        if _, ok := err.(scerr.ErrNotFound); ok {
            return err
        }
        return err
    }

    err = handler.isAlreadyMounted(ctx, hostName, volume)
    if err != nil {
        return err
    }

    var slicesAttachedSoFar []string

    defer func() {
        if err != nil {
            if len(slicesAttachedSoFar) != 0 {
                logrus.Debugln("attachLVM cleanup : detaching volumes after failure...")
            }
            for _, volSlice := range slicesAttachedSoFar {
                nerr := handler.Detach(ctx, volSlice, hostName)
                if nerr != nil {
                    logrus.Debugf("attachLVM cleanup : error detaching volume %s", volSlice)
                }
            }
        }
    }()

    var deviceNames []string
    for _, volumeSlice := range volume.PVM {
        devName, err := handler.Attach(ctx, volumeSlice.Name, hostName, path, format, doNotFormat)
        if err != nil {
            return err
        }

        slicesAttachedSoFar = append(slicesAttachedSoFar, volumeSlice.Name)

        if devName != "" {
            deviceNames = append(deviceNames, devName)
        }
    }

    // Get Host data
    hostSvc := NewHostHandler(handler.service)
    host, err := hostSvc.ForceInspect(ctx, hostName)
    if err != nil {
        return err
    }

    // Create mount point
    sshHandler := NewSSHHandler(handler.service)
    sshConfig, err := sshHandler.GetConfig(ctx, host.ID)
    if err != nil {
        return err
    }

    server, err := nfs.NewServer(sshConfig)
    if err != nil {
        return err
    }

    outInfo, err := server.MountVGDevice("", volumeName, format, doNotFormat, deviceNames)
    if err != nil {
        return err
    }

    if !doNotFormat {
        var newIds []string

        for _, line := range strings.Split(outInfo, "\n") {
            if strings.HasPrefix(line, "SS:MOUNTED") {
                newIds = append(newIds, strings.Split(line, ":")[2])
            }
        }

        if len(newIds) == 0 {
            return fmt.Errorf("unable to detect mounted devices")
        }

        lvmId := newIds[len(newIds)-1]

        mountPoint := path
        if path == resources.DefaultVolumeMountPoint {
            mountPoint = resources.DefaultVolumeMountPoint + volume.Name
        }

        // Updates volume properties
        err = volume.Properties.LockForWrite(volumeproperty.AttachedV1).ThenUse(
            func(data data.Clonable) error {
                volumeAttachedV1 := data.(*propsv1.VolumeAttachments)
                volumeAttachedV1.Hosts[host.ID] = host.Name
                return nil
            },
        )
        if err != nil {
            return err
        }

        for ind, volumeSlice := range volume.PVM {
            cuvol, _, err := handler.Inspect(ctx, volumeSlice.Name)
            if err != nil {
                return err
            }

            logrus.Debugf("Working with volume with ID %s", volumeSlice.ID)
            var previous string

            err = host.Properties.LockForWrite(hostproperty.VolumesV1).ThenUse(
                func(data data.Clonable) error {
                    hostVolumesV1 := data.(*propsv1.HostVolumes)

                    previous = hostVolumesV1.DevicesByID[volumeSlice.ID]
                    logrus.Debugf("We should remove the local_mount_by_device with %s", previous)

                    delete(hostVolumesV1.DevicesByID, volume.ID)
                    logrus.Debugf("Updating UUID to %s", newIds[ind])
                    err = hostVolumesV1.UpdateUUID(cuvol.ID, newIds[ind])
                    if err != nil {
                        return err
                    }
                    return nil
                },
            )
            if err != nil {
                return scerr.Wrap(err, "can't attach volume")
            }

            localMountPoint := mountPoint + "_lvm_" + strconv.Itoa(ind)
            err = host.Properties.LockForWrite(hostproperty.MountsV1).ThenUse(
                func(data data.Clonable) error {
                    // Updates host properties
                    hostMountsV1 := data.(*propsv1.HostMounts)

                    hostMountsV1.LocalMountsByPath[localMountPoint] = &propsv1.HostLocalMount{
                        Device:     newIds[ind],
                        Path:       localMountPoint,
                        FileSystem: format,
                        Options:    "lvm",
                    }

                    delete(hostMountsV1.LocalMountsByDevice, previous)

                    hostMountsV1.LocalMountsByDevice[newIds[ind]] = mountPoint + "_lvm_" + strconv.Itoa(ind)
                    logrus.Warnf("Storing in LVM LocalMountsByDevice [%s], [%s]", newIds[ind], mountPoint+"_lvm_"+strconv.Itoa(ind))
                    return nil
                },
            )
            if err != nil {
                return scerr.Wrap(err, "can't attach volume")
            }

            // FIXME Verfication
            err = host.Properties.LockForRead(hostproperty.MountsV1).ThenUse(
                func(data data.Clonable) error {
                    // Updates host properties
                    hostMountsV1 := data.(*propsv1.HostMounts)
                    logrus.Warnf("Reading gives: %s", hostMountsV1.LocalMountsByPath[localMountPoint].Options)
                    return nil
                },
            )
            if err != nil {
                return scerr.Wrap(err, "can't attach volume")
            }

            _, err = metadata.SaveHost(handler.service, host)
            if err != nil {
                return scerr.Wrap(err, "can't attach volume")
            }
            // _ = sh.Write()
        }

        err = host.Properties.LockForWrite(hostproperty.VolumesV1).ThenUse(
            func(data data.Clonable) error {
                hostVolumesV1 := data.(*propsv1.HostVolumes)
                reset := volume.Name + "-" + host.Name
                hostVolumesV1.AddHostVolume(volume.ID, volume.Name, reset, lvmId)
                return nil
            },
        )
        if err != nil {
            return scerr.Wrap(err, "can't attach volume")
        }

        // FIXME new attachment ID problematic

        err = host.Properties.LockForWrite(hostproperty.MountsV1).ThenUse(
            func(data data.Clonable) error {
                hostMountsV1 := data.(*propsv1.HostMounts)
                // Updates host properties
                hostMountsV1.LocalMountsByPath[mountPoint] = &propsv1.HostLocalMount{
                    Device:     lvmId,
                    Path:       mountPoint,
                    FileSystem: format,
                    Options:    "lvm",
                }
                hostMountsV1.LocalMountsByDevice[lvmId] = mountPoint
                logrus.Warnf("Storing in LVM attachment LocalMountsByDevice [%s], [%s]", lvmId, mountPoint)
                return nil
            },
        )
        if err != nil {
            return scerr.Wrap(err, "can't attach volume")
        }

        _, err = metadata.SaveHost(handler.service, host)
        if err != nil {
            return scerr.Wrap(err, "can't attach volume")
        }

        if !doNotFormat {
            volume.Formatted = true
        }

        _, err = metadata.SaveVolume(handler.service, volume)
        if err != nil {
            return scerr.Wrap(err, "can't attach volume")
        }

        logrus.Debugf("Recovered info: [%s]", outInfo)
    } else {
        var lvmId string

        var newIds []string

        for _, line := range strings.Split(outInfo, "\n") {
            if strings.HasPrefix(line, "SS:MOUNTEDPV") {
                newIds = append(newIds, strings.Split(line, ":")[2])
            }
            if strings.HasPrefix(line, "SS:MOUNTEDLV") {
                lvmId = strings.Split(line, ":")[2]
            }
        }

        err = host.Properties.LockForWrite(hostproperty.VolumesV1).ThenUse(
            func(data data.Clonable) error {
                hostVolumesV1 := data.(*propsv1.HostVolumes)
                reset := volume.Name + "-" + host.Name
                hostVolumesV1.AddHostVolume(volume.ID, volume.Name, reset, lvmId)
                return nil
            },
        )
        if err != nil {
            return scerr.Wrap(err, "can't attach volume")
        }

        _, err = metadata.SaveHost(handler.service, host)
        if err != nil {
            return scerr.Wrap(err, "can't attach volume")
        }

        err = volume.Properties.LockForWrite(volumeproperty.AttachedV1).ThenUse(
            func(data data.Clonable) error {
                volumeAttachedV1 := data.(*propsv1.VolumeAttachments)
                // Updates volume properties
                volumeAttachedV1.Hosts[host.ID] = host.Name
                return nil
            },
        )
        if err != nil {
            return scerr.Wrap(err, "can't attach volume")
        }

        _, err = metadata.SaveVolume(handler.service, volume)
        if err != nil {
            return scerr.Wrap(err, "can't attach volume")
        }

        // FIXME use functions to handle structs

        mountPoint := path
        if path == resources.DefaultVolumeMountPoint {
            mountPoint = resources.DefaultVolumeMountPoint + volume.Name
        }

        err = host.Properties.LockForWrite(hostproperty.MountsV1).ThenUse(
            func(nd data.Clonable) error {
                hostMountsV1 := nd.(*propsv1.HostMounts)
                for ind, volumeSlice := range volume.PVM {
                    cuvol, _, err := handler.Inspect(ctx, volumeSlice.Name)
                    if err != nil {
                        return err
                    }

                    err = host.Properties.LockForWrite(hostproperty.VolumesV1).ThenUse(
                        func(data data.Clonable) error {
                            hostVolumesV1 := data.(*propsv1.HostVolumes)
                            err = hostVolumesV1.UpdateUUID(cuvol.ID, newIds[ind])
                            return err
                        },
                    )
                    if err != nil {
                        return err
                    }

                    // Updates host properties
                    hostMountsV1.LocalMountsByPath[mountPoint] = &propsv1.HostLocalMount{
                        Device:     newIds[ind],
                        Path:       mountPoint + "_lvm_" + strconv.Itoa(ind),
                        FileSystem: format,
                        Options:    "lvm",
                    }
                    hostMountsV1.LocalMountsByDevice[newIds[ind]] = mountPoint + "_lvm_" + strconv.Itoa(ind)
                }

                // Updates host properties
                hostMountsV1.LocalMountsByPath[mountPoint] = &propsv1.HostLocalMount{
                    Device:     lvmId,
                    Path:       mountPoint,
                    FileSystem: format,
                    Options:    "lvm",
                }
                hostMountsV1.LocalMountsByDevice[lvmId] = mountPoint
                return nil
            },
        )
        if err != nil {
            return scerr.Wrap(err, "can't attach volume")
        }

        _, err = metadata.SaveHost(handler.service, host)
        if err != nil {
            return scerr.Wrap(err, "can't attach volume")
        }

        return nil
    }

    return nil
}

func (handler *VolumeHandler) listAttachedDevices(ctx context.Context, host *resources.Host) (set mapset.Set, err error) {
    if handler == nil {
        return nil, scerr.InvalidInstanceError()
    }
    // FIXME: validate parameters

    defer scerr.OnExitLogError(debug.NewTracer(nil, "", true).TraceMessage(""), &err)()

    sshHandler := NewSSHHandler(handler.service)

    // retrieve ssh config to perform some commands
    ssh, err := sshHandler.GetConfig(ctx, host.ID)
    if err != nil {
        return nil, err
    }
    cmd := "sudo lsblk -l -o NAME,TYPE | grep disk | cut -d' ' -f1"
    sshCmd, err := ssh.Command(cmd)
    if err != nil {
        return nil, err
    }

    var (
        retcode        int
        stdout, stderr string
    )
    retryErr := retry.WhileUnsuccessfulDelay1Second(
        func() error {
            retryErr := retry.WhileUnsuccessfulDelay1SecondWithNotify(
                func() error {
                    retcode, stdout, stderr, err = sshCmd.RunWithTimeout(nil, outputs.COLLECT, temporal.GetHostTimeout())
                    return err
                },
                temporal.GetHostTimeout(),
                func(t retry.Try, v verdict.Enum) {
                    if v == verdict.Retry {
                        logrus.Debugf("Remote SSH service on host '%s' isn't ready, retrying...", host.Name)
                    }
                },
            )
            if retryErr != nil {
                return retryErr
            }
            if retcode != 0 {
                if retcode == 255 {
                    return fmt.Errorf("failed to reach SSH service of host '%s', retrying", host.Name)
                }
                return fmt.Errorf(stderr)
            }
            return nil
        },
        temporal.GetContextTimeout(),
    )
    if retryErr != nil {
        return nil, scerr.Wrap(
            retryErr, fmt.Sprintf("failed to get list of connected disks after %s", temporal.GetContextTimeout()),
        )
    }
    disks := strings.Split(stdout, "\n")
    set = mapset.NewThreadUnsafeSet()
    for _, k := range disks {
        set.Add(k)
    }
    return set, nil
}

func getServer(ctx context.Context, handler *VolumeHandler, hostName string) (*nfs.Server, error) {
    // Get Host data
    hostSvc := NewHostHandler(handler.service)
    host, err := hostSvc.ForceInspect(ctx, hostName)
    if err != nil {
        return nil, err
    }

    sshHandler := NewSSHHandler(handler.service)
    sshConfig, err := sshHandler.GetConfig(ctx, host.ID)
    if err != nil {
        return nil, scerr.Wrap(err, "error getting ssh config")
    }
    server, err := nfs.NewServer(sshConfig)
    if err != nil {
        return nil, err
    }

    return server, nil
}

func getServerByID(ctx context.Context, handler *VolumeHandler, hostID string) (server *nfs.Server, err error) {
    sshHandler := NewSSHHandler(handler.service)
    sshConfig, err := sshHandler.GetConfig(ctx, hostID)
    if err != nil {
        return nil, scerr.Wrap(err, "error getting ssh config")
    }
    server, err = nfs.NewServer(sshConfig)
    if err != nil {
        return nil, err
    }

    return server, nil
}

func getHostLocalMount(ctx context.Context, handler *VolumeHandler, volumeName, hostName string) (
    mount *propsv1.HostLocalMount, err error,
) {
    // Get Host data
    hostSvc := NewHostHandler(handler.service)
    host, err := hostSvc.ForceInspect(ctx, hostName)
    if err != nil {
        return nil, scerr.Wrap(err, fmt.Sprintf("failure inspecting host %s", hostName))
    }

    // Load volume data
    volume, _, err := handler.Inspect(ctx, volumeName)
    if err != nil {
        if _, ok := err.(scerr.ErrNotFound); !ok {
            return nil, err
        }
        return nil, resources.ResourceNotFoundError("volume", volumeName)
    }

    var attachment *propsv1.HostVolume

    // Obtain volume attachment ID
    err = host.Properties.LockForRead(hostproperty.VolumesV1).ThenUse(
        func(data data.Clonable) error {
            hostVolumesV1 := data.(*propsv1.HostVolumes)
            att, found := hostVolumesV1.VolumesByID[volume.ID]
            if !found {
                return scerr.Errorf(fmt.Sprintf("Can't detach volume '%s': not attached to host '%s'", volumeName, host.Name), nil)
            }
            attachment = att
            return nil
        },
    )
    if err != nil {
        return nil, scerr.Wrap(err, "")
    }

    // Obtain mounts information
    err = host.Properties.LockForRead(hostproperty.MountsV1).ThenUse(
        func(data data.Clonable) error {
            hostMountsV1 := data.(*propsv1.HostMounts)
            device := attachment.Device
            path := hostMountsV1.LocalMountsByDevice[device]
            mount = hostMountsV1.LocalMountsByPath[path]
            if mount == nil {
                return scerr.Errorf(fmt.Sprintf("metadata inconsistency: no mount corresponding to volume attachment"), nil)
            }
            return nil
        },
    )
    if err != nil {
        return nil, scerr.Wrap(err, "")
    }

    return mount, nil
}

// Detach detach the volume identified by ref, ref can be the name or the id
func (handler *VolumeHandler) Expand(
    ctx context.Context, volumeName, hostName string, increment uint32, incrementType string,
) (err error) {
    // Load volume data
    volume, _, err := handler.Inspect(ctx, volumeName)
    if err != nil {
        if _, ok := err.(scerr.ErrNotFound); !ok {
            return err
        }
        return resources.ResourceNotFoundError("volume", volumeName)
    }

    if !volume.ManagedByLVM {
        return resources.ResourceInvalidRequestError("volume", "Standard volumes cannot be expandad")
    }

    if len(volume.PVM) == 0 {
        return resources.ResourceInvalidRequestError(
            "volume", "Physical volumes cannot be expanded, only the volume group can be expanded",
        )
    }

    vuSize := volume.Size / len(volume.PVM)
    valids := []string{"gb", "uv", "ratio"}
    validChange := false
    for _, item := range valids {
        if incrementType == item {
            validChange = true
        }
    }

    // that should never happen, consider panicking instead
    if !validChange {
        return resources.ResourceInvalidRequestError("volume", "Unknown size parameter")
    }

    nun := uint32(0)

    if incrementType == "gb" {
        nun = uint32(math.Ceil(float64(float64(increment) / float64(vuSize))))
        logrus.Debugf("We have to create volumes of %d Gb, working with units of %d Gb size, %d volumes", increment, vuSize, nun)
    }

    if incrementType == "uv" {
        nun = increment
        logrus.Debugf("We have to add %d volumes of %d Gb each", increment, vuSize)
    }

    if incrementType == "ratio" {
        targetVol := float64(volume.Size) * float64(increment) / (100 * float64(vuSize))
        nun = uint32(math.Ceil(float64(targetVol)))
        logrus.Debugf("After some maths, we need to add %d volumes of %d Gb each", nun, vuSize)
    }

    mountInfo, err := getHostLocalMount(ctx, handler, volumeName, hostName)
    if err != nil {
        return scerr.Wrap(err, "")
    }
    logrus.Debugf("Volume path [%s], filesystem [%s]", mountInfo.Path, mountInfo.FileSystem)

    var deviceNames []string
    var createdVolumes []*resources.Volume

    defer func() {
        if err != nil {
            logrus.Debugf("Expand cleanup : cleaning volumes...")
            for _, vol := range createdVolumes {
                errRemovingVolume := handler.service.DeleteVolume(vol.ID)
                if errRemovingVolume != nil {
                    logrus.Debugf("Expand cleanup : error removing volume: %s", errRemovingVolume.Error())
                } else {
                    errorDeletingVolume := metadata.RemoveVolume(handler.service, vol.ID)
                    if errorDeletingVolume != nil {
                        logrus.Debugf("Expand cleanup : error removing volume metadata: %s", errorDeletingVolume.Error())
                    } else {
                        logrus.Debugf("Expand cleanup : cleaned volume %s", vol.Name)
                    }
                }
            }
        }
    }()

    for tba := 0; tba < int(nun); tba++ {

        newVolume, err := handler.service.CreateVolume(
            resources.VolumeRequest{
                Name:   volume.Name + "_lvm_" + strconv.Itoa(len(volume.PVM)+tba),
                Size:   vuSize,
                Speed:  volume.Speed,
                InLVM:  true,
                SizeVU: vuSize,
            },
        )

        if err != nil {
            return scerr.Wrap(err, "")
        }

        newVolume.ManagedByLVM = true
        createdVolumes = append(createdVolumes, newVolume)

        _, err = metadata.SaveVolume(handler.service, newVolume)
        if err != nil {
            logrus.Debugf("Error creating volume: saving volume metadata: %+v", err)
            return scerr.Wrap(err, fmt.Sprintf("Error creating volume '%s' saving its volume metadata", newVolume.Name))
        }

        devName, err := handler.Attach(
            ctx, newVolume.Name, hostName, mountInfo.Path+"_lvm_"+strconv.Itoa(len(volume.PVM)+tba), mountInfo.FileSystem, false,
        )
        if err != nil {
            logrus.Debugf("Error attaching volume: %v", err.Error())
            return err
        }
        if devName != "" {
            deviceNames = append(deviceNames, devName)
        }
    }

    server, err := getServer(ctx, handler, hostName)
    if err != nil {
        return err
    }

    // FIXME Use recovered info from string
    _, err = server.ExpandVGDevice("", volumeName, mountInfo.FileSystem, false, deviceNames)
    if err != nil {
        return err
    }

    for _, addedVol := range createdVolumes {
        volume.PVM = append(volume.PVM, addedVol)
        volume.Size = volume.Size + addedVol.Size
    }

    _, err = metadata.SaveVolume(handler.service, volume)
    if err != nil {
        logrus.Debugf("Error creating volume: saving volume metadata: %+v", err)
        return scerr.Wrap(err, fmt.Sprintf("Error creating volume '%s' saving its volume metadata", volume.Name))
    }

    return nil
}

// Detach detach the volume identified by ref, ref can be the name or the id
func (handler *VolumeHandler) Shrink(
    ctx context.Context, volumeName, hostName string, increment uint32, incrementType string,
) (err error) {
    if handler == nil {
        return scerr.InvalidInstanceError()
    }
    // FIXME: validate parameters

    // Load volume data
    volume, _, err := handler.Inspect(ctx, volumeName)
    if err != nil {
        if _, ok := err.(scerr.ErrNotFound); !ok {
            return err
        }
        return resources.ResourceNotFoundError("volume", volumeName)
    }

    if !volume.ManagedByLVM {
        return fmt.Errorf("standard volumes cannot be shrinked")
    }

    if len(volume.PVM) == 0 {
        return fmt.Errorf("physical volumes cannot be shrinked, only the group can be shrinked")
    }

    vuSize := volume.Size / len(volume.PVM)
    valids := []string{"gb", "uv", "ratio"}
    validChange := false
    for _, item := range valids {
        if incrementType == item {
            validChange = true
        }
    }

    if !validChange {
        return fmt.Errorf("unknown size parameter")
    }

    numberOfVolumeUnitsAffected := uint32(0)
    wantedSizeInGb := volume.Size

    if incrementType == "gb" {
        numberOfVolumeUnitsAffected = uint32(math.Ceil(float64(float64(increment) / float64(vuSize))))
        logrus.Debugf(
            "We have to remove volumes of %d Gb, working with units of %d Gb size, %d volumes", increment, vuSize,
            numberOfVolumeUnitsAffected,
        )
        wantedSizeInGb = wantedSizeInGb - int(increment)
    }

    if incrementType == "uv" {
        numberOfVolumeUnitsAffected = increment
        logrus.Debugf("We have to add %d volumes of %d Gb each", increment, vuSize)
        wantedSizeInGb = wantedSizeInGb - (int(increment) * int(vuSize))
    }

    if incrementType == "ratio" {
        targetVol := float64(volume.Size) * float64(increment) / (100 * float64(vuSize))
        numberOfVolumeUnitsAffected = uint32(math.Ceil(float64(targetVol)))
        wantedSizeInGb = wantedSizeInGb - int(float64(volume.Size)*float64(increment)/float64(100))
    }

    if incrementType == "" {
        logrus.Debugf("Resize to a minimum by default")
    }

    logrus.Debugf("We have a target size from %d to %d Gb", volume.Size, wantedSizeInGb)

    mountInfo, err := getHostLocalMount(ctx, handler, volumeName, hostName)
    if err != nil {
        return err
    }
    logrus.Debugf("Volume path [%s], filesystem [%s]", mountInfo.Path, mountInfo.FileSystem)

    var deviceNames []string

    server, err := getServer(ctx, handler, hostName)
    if err != nil {
        return err
    }

    shrinkOutput, err := server.ShrinkVGDevice("", volumeName, mountInfo.FileSystem, false, deviceNames, vuSize, wantedSizeInGb)
    if err != nil {
        if strings.Contains(shrinkOutput, "SS:FAILURE:") {
            lines := strings.Split(shrinkOutput, "\n")
            for _, line := range lines {
                if strings.HasPrefix(line, "SS:FAILURE:") {
                    fragments := strings.Split(line, ":")
                    return scerr.Wrap(err, fragments[2])
                }
            }

        }
        return err
    }

    // FIXME Rename structs
    type smp struct {
        uuid       string
        mountpoint string
    }

    var points []smp

    lines := strings.Split(shrinkOutput, "\n")
    for _, line := range lines {
        if strings.HasPrefix(line, "SS:DELETED:") {
            logrus.Debugf("We had some shrink output: [%s]", line)
            fragments := strings.Split(line, ":")
            points = append(points, smp{uuid: fragments[2], mountpoint: fragments[3]})
        }
    }

    host, err := getHost(ctx, handler, hostName)
    if err != nil {
        return err
    }

    hostVolumesV1, err := getHostVolume(ctx, handler, hostName)
    if err != nil {
        return err
    }

    for _, point := range points {
        vod, ok := hostVolumesV1.VolumesByDevice[point.uuid]
        if ok {
            hovol := hostVolumesV1.VolumesByID[vod]
            logrus.Debugf("We have to delete : [%s], attachment [%s]", hovol.Device, hovol.AttachID)
            errRemovingAttachment := handler.service.DeleteVolumeAttachment(host.ID, hovol.AttachID)

            failed := false
            if errRemovingAttachment != nil {
                failed = true
                logrus.Debugf("Error removing volume attachment: %s", errRemovingAttachment.Error())
            } else {
                logrus.Debugf("Removed volume attachment [%s]", hovol.AttachID)
            }
            errRemovingVolume := handler.service.DeleteVolume(vod)
            if errRemovingVolume != nil {
                failed = true
                logrus.Debugf("Error removing volume: %s", errRemovingVolume.Error())
            } else {
                logrus.Debugf("Removed volume [%s]", vod)
            }

            if !failed {
                // update volume PVMs
                var na []*resources.Volume
                for _, v := range volume.PVM {
                    if v.ID == vod {
                        continue
                    } else {
                        na = append(na, v)
                    }
                }
                volume.PVM = na
                volume.Size = volume.Size - vuSize
            }
        }
    }

    _, err = metadata.SaveVolume(handler.service, volume)
    if err != nil {
        logrus.Debugf("Error creating volume: saving volume metadata: %+v", err)
        return scerr.Wrap(err, fmt.Sprintf("Error creating volume '%s' saving its volume metadata", volume.Name))
    }

    return nil
}

// Detach detach the volume identified by ref, ref can be the name or the id
func (handler *VolumeHandler) Detach(ctx context.Context, volumeName, hostName string) (err error) {
    if handler == nil {
        return scerr.InvalidInstanceError()
    }
    // FIXME: validate parameters

    tracer := debug.NewTracer(nil, fmt.Sprintf("('%s', '%s')", volumeName, hostName), true).WithStopwatch().GoingIn()
    defer tracer.OnExitTrace()()
    defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

    // Load volume data
    volume, _, err := handler.Inspect(ctx, volumeName)
    if err != nil {
        if _, ok := err.(scerr.ErrNotFound); !ok {
            return err
        }
        return resources.ResourceNotFoundError("volume", volumeName)
    }
    mountPath := ""

    // Load host data
    hostSvc := NewHostHandler(handler.service)
    host, err := hostSvc.ForceInspect(ctx, hostName)
    if err != nil {
        return err
    }

    // Obtain volume attachment ID
    err = host.Properties.LockForWrite(hostproperty.VolumesV1).ThenUse(
        func(clonable data.Clonable) error {
            hostVolumesV1 := clonable.(*propsv1.HostVolumes)

            // Check the volume is effectively attached
            attachment, found := hostVolumesV1.VolumesByID[volume.ID]
            if !found {
                return fmt.Errorf("cannot detach volume '%s': not attached to host '%s'", volumeName, host.Name)
            }

            // Obtain mounts information
            return host.Properties.LockForWrite(hostproperty.MountsV1).ThenUse(
                func(clonable data.Clonable) error {
                    hostMountsV1 := clonable.(*propsv1.HostMounts)
                    device := attachment.Device
                    mountPath = hostMountsV1.LocalMountsByDevice[device]
                    mount := hostMountsV1.LocalMountsByPath[mountPath]
                    if mount == nil {
                        return fmt.Errorf("metadata inconsistency: no mount corresponding to volume attachment")
                    }

                    // Check if volume has other mount(s) inside it
                    for p, i := range hostMountsV1.LocalMountsByPath {
                        if i.Device == device {
                            continue
                        }
                        if strings.Index(p, mount.Path) == 0 {
                            return fmt.Errorf(
                                "cannot detach volume '%s' from '%s:%s', there is a volume mounted in '%s:%s'",
                                volume.Name, host.Name, mount.Path, host.Name, p,
                            )
                        }
                    }
                    for p := range hostMountsV1.RemoteMountsByPath {
                        if strings.Index(p, mount.Path) == 0 {
                            return fmt.Errorf(
                                "cannot detach volume '%s' from '%s:%s', there is a share mounted in '%s:%s'",
                                volume.Name, host.Name, mount.Path, host.Name, p,
                            )
                        }
                    }

                    // Check if volume (or a subdir in volume) is shared
                    return host.Properties.LockForWrite(hostproperty.SharesV1).ThenUse(
                        func(clonable data.Clonable) error {
                            hostSharesV1 := clonable.(*propsv1.HostShares)

                            for _, v := range hostSharesV1.ByID {
                                if strings.Index(v.Path, mount.Path) == 0 {
                                    return fmt.Errorf(
                                        "cannot detach volume '%s' from '%s:%s', '%s:%s' is shared",
                                        volume.Name, host.Name, mount.Path, host.Name, v.Path,
                                    )
                                }
                            }

                            // Unmount the Block Device ...
                            sshHandler := NewSSHHandler(handler.service)
                            sshConfig, err := sshHandler.GetConfig(ctx, host.ID)
                            if err != nil {
                                return err
                            }
                            nfsServer, err := nfs.NewServer(sshConfig)
                            if err != nil {
                                return err
                            }
                            err = nfsServer.UnmountBlockDevice(attachment.Device)
                            if err != nil {
                                // FIXME Think about this
                                logrus.Error(err)
                                // return err
                            }

                            // ... then detach volume
                            err = handler.service.DeleteVolumeAttachment(host.ID, attachment.AttachID)
                            if err != nil {
                                switch err.(type) {
                                case scerr.ErrNotFound, scerr.ErrInvalidRequest, scerr.ErrTimeout:
                                    return err
                                default:
                                    return err
                                }
                            }

                            // Updates host property propsv1.VolumesV1
                            delete(hostVolumesV1.VolumesByID, volume.ID)
                            delete(hostVolumesV1.VolumesByName, volume.Name)
                            delete(hostVolumesV1.VolumesByDevice, attachment.Device)
                            delete(hostVolumesV1.DevicesByID, volume.ID)

                            // Updates host property propsv1.MountsV1
                            delete(hostMountsV1.LocalMountsByDevice, mount.Device)
                            delete(hostMountsV1.LocalMountsByPath, mount.Path)

                            // Updates volume property propsv1.VolumeAttachments
                            return volume.Properties.LockForWrite(volumeproperty.AttachedV1).ThenUse(
                                func(clonable data.Clonable) error {
                                    volumeAttachedV1 := clonable.(*propsv1.VolumeAttachments)
                                    delete(volumeAttachedV1.Hosts, host.ID)
                                    return nil
                                },
                            )
                        },
                    )
                },
            )
        },
    )
    if err != nil {
        return err
    }

    // Updates metadata
    _, err = metadata.SaveHost(handler.service, host)
    if err != nil {
        return err
    }
    _, err = metadata.SaveVolume(handler.service, volume)
    if err != nil {
        return err
    }

    select {
    case <-ctx.Done():
        logrus.Warnf("Volume detachment cancelled by user")
        // Currently format is not registered anywhere so we use ext4 the most common format (but as we mount the volume the format parameter is ignored anyway)
        _, err = handler.Attach(context.Background(), volumeName, hostName, mountPath, "ext4", true)
        if err != nil {
            return fmt.Errorf("failed to stop volume detachment")
        }
        return fmt.Errorf("volume detachment cancelled by user")
    default:
    }

    return nil
}
