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

package gcp

import (
    "fmt"
    "strconv"
    "time"

    "github.com/davecgh/go-spew/spew"
    uuid "github.com/satori/go.uuid"
    "github.com/sirupsen/logrus"
    "google.golang.org/api/compute/v1"
    "google.golang.org/api/googleapi"

    "github.com/CS-SI/SafeScale/lib/utils/debug"
    "github.com/CS-SI/SafeScale/lib/utils/debug/tracing"

    "github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
    "github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
    "github.com/CS-SI/SafeScale/lib/server/resources/abstract"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
    "github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
    "github.com/CS-SI/SafeScale/lib/utils"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
    "github.com/CS-SI/SafeScale/lib/utils/retry"
    "github.com/CS-SI/SafeScale/lib/utils/strprocess"
    "github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// -------------IMAGES---------------------------------------------------------------------------------------------------

// ListImages lists available OS images
func (s *Stack) ListImages() (images []abstract.Image, err fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }

    compuService := s.ComputeService

    images = []abstract.Image{}

    families := []string{"centos-cloud", "debian-cloud", "rhel-cloud", "ubuntu-os-cloud", "suse-cloud", "rhel-sap-cloud", "suse-sap-cloud"}

    for _, family := range families {
        token := ""
        for paginate := true; paginate; {
            resp, err := compuService.Images.List(family).Filter("deprecated.replacement ne .*images.*").PageToken(token).Do()
            if err != nil {
                logrus.Warnf("Can't list public images for project %q", family)
                break
            }

            for _, image := range resp.Items {
                images = append(images, abstract.Image{Name: image.Name, URL: image.SelfLink, ID: strconv.FormatUint(image.Id, 10)})
            }
            token := resp.NextPageToken
            paginate = token != ""
        }
    }

    if len(images) == 0 {
        return images, err
    }

    return images, nil
}

// GetImage returns the Image referenced by id
func (s *Stack) GetImage(id string) (*abstract.Image, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }
    if id == "" {
        return nil, fail.InvalidParameterError("id", "cannot be empty string")
    }

    images, err := s.ListImages()
    if err != nil {
        return nil, err
    }

    for _, image := range images {
        if image.ID == id {
            return &image, nil
        }
    }

    return nil, fail.NotFoundError("image with id '%s' not found", id)
}

// -------------TEMPLATES------------------------------------------------------------------------------------------------

// ListTemplates overload OpenStackGcp ListTemplate method to filter wind and flex instance and add GPU configuration
func (s *Stack) ListTemplates(all bool) (templates []abstract.HostTemplate, err fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }

    compuService := s.ComputeService

    templates = []abstract.HostTemplate{}

    token := ""
    for paginate := true; paginate; {
        resp, err := compuService.MachineTypes.List(s.GcpConfig.ProjectID, s.GcpConfig.Zone).PageToken(token).Do()
        if err != nil {
            logrus.Warnf("Can't list public types...: %s", err)
            break
        } else {

            for _, matype := range resp.Items {
                ht := abstract.HostTemplate{
                    Cores:   int(matype.GuestCpus),
                    RAMSize: float32(matype.MemoryMb / 1024),
                    // VPL: GCP Template disk sizing is ridiculous at best, so fill it to 0 and let us size the disk ourselves
                    // DiskSize: int(matype.ImageSpaceGb),
                    DiskSize: 0,
                    ID:       strconv.FormatUint(matype.Id, 10),
                    Name:     matype.Name,
                }
                templates = append(templates, ht)
            }
        }
        token := resp.NextPageToken
        paginate = token != ""
    }

    if len(templates) == 0 {
        return templates, err
    }

    return templates, nil
}

// GetTemplate overload OpenStackGcp GetTemplate method to add GPU configuration
func (s *Stack) GetTemplate(id string) (*abstract.HostTemplate, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }
    if id == "" {
        return nil, fail.InvalidParameterError("id", "cannot be empty string")
    }

    templates, err := s.ListTemplates(true)
    if err != nil {
        return nil, err
    }

    for _, template := range templates {
        if template.ID == id {
            return &template, nil
        }
    }

    return nil, fail.NotFoundError("template with id '%s' not found", id)
}

// -------------SSH KEYS-------------------------------------------------------------------------------------------------

// CreateKeyPair creates and import a key pair
func (s *Stack) CreateKeyPair(name string) (*abstract.KeyPair, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }
    if name == "" {
        return nil, fail.InvalidParameterError("name", "cannot be empty string")
    }

    // privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    // publicKey := privateKey.PublicKey
    // pub, _ := ssh.NewPublicKey(&publicKey)
    // pubBytes := ssh.MarshalAuthorizedKey(pub)
    // pubKey := string(pubBytes)

    // priBytes := x509.MarshalPKCS1PrivateKey(privateKey)
    // priKeyPem := pem.EncodeToMemory(
    // 	&pem.Block{
    // 		Type:  "RSA PRIVATE KEY",
    // 		Bytes: priBytes,
    // 	},
    // )
    // priKey := string(priKeyPem)
    // return &resources.KeyPair{
    // 	ID:         name,
    // 	Name:       name,
    // 	PublicKey:  pubKey,
    // 	PrivateKey: priKey,
    // }, nil
    return abstract.NewKeyPair(name)
}

// GetKeyPair returns the key pair identified by id
func (s *Stack) GetKeyPair(id string) (*abstract.KeyPair, fail.Error) {
    return nil, fail.NotImplementedError("GetKeyPair() not implemented yet") // FIXME: Technical debt
}

// ListKeyPairs lists available key pairs
func (s *Stack) ListKeyPairs() ([]abstract.KeyPair, fail.Error) {
    return nil, fail.NotImplementedError("ListKeyPairs() not implemented yet") // FIXME: Technical debt
}

// DeleteKeyPair deletes the key pair identified by id
func (s *Stack) DeleteKeyPair(id string) fail.Error {
    return fail.NotImplementedError("DeleteKeyPair() not implemented yet") // FIXME: Technical debt
}

// CreateHost creates an host satisfying request
func (s *Stack) CreateHost(request abstract.HostRequest) (ahf *abstract.HostFull, userData *userdata.Content, xerr fail.Error) {
    nullAhf := abstract.NewHostFull()
    nullUd := userdata.NewContent()
    if s == nil {
        return nullAhf, nullUd, fail.InvalidInstanceError()
    }

    defer fail.OnPanic(&xerr)

    resourceName := request.ResourceName
    networks := request.Networks
    hostMustHavePublicIP := request.PublicIP

    if len(networks) == 0 {
        return nullAhf, nullUd, fail.InvalidRequestError("the host %s must be on at least one network (even if public)", resourceName)
    }

    // If no key pair is supplied create one
    if request.KeyPair == nil {
        id, err := uuid.NewV4()
        if err != nil {
            msg := fmt.Sprintf("failed to create host UUID: %s", err.Error())
            logrus.Debugf(strprocess.Capitalize(msg))
            return nullAhf, nullUd, fail.NewError(msg)
        }

        name := fmt.Sprintf("%s_%s", request.ResourceName, id)
        request.KeyPair, err = s.CreateKeyPair(name)
        if err != nil {
            msg := fmt.Sprintf("failed to create host key pair: %s", err.Error())
            logrus.Debugf(strprocess.Capitalize(msg))
            return nullAhf, nullUd, fail.NewError(msg)
        }
    }
    if request.Password == "" {
        password, err := utils.GeneratePassword(16)
        if err != nil {
            return nullAhf, nullUd, fail.NewError("failed to generate password: %s", err.Error())
        }
        request.Password = password
    }

    // The Default Network is the first of the provided list, by convention
    defaultNetwork := request.Networks[0]
    defaultNetworkID := defaultNetwork.ID
    isGateway := defaultNetwork == nil // || defaultNetwork.Name == abstract.SingleHostNetworkName

    // if defaultGateway == nil && !hostMustHavePublicIP {
    if request.DefaultRouteIP == "" && !hostMustHavePublicIP {
        return nullAhf, nullUd, fail.InvalidRequestError("the host '%s' must have a gateway or be public", resourceName)
    }

    // --- prepares data structures for Provider usage ---

    // Constructs userdata content
    userData = userdata.NewContent()
    xerr = userData.Prepare(*s.Config, request, defaultNetwork.CIDR, "")
    if xerr != nil {
        xerr = fail.Wrap(xerr, "failed to prepare user data content")
        logrus.Debugf(strprocess.Capitalize(xerr.Error()))
        return nullAhf, nullUd, xerr
    }

    // Determine system disk size based on vcpus count
    template, xerr := s.GetTemplate(request.TemplateID)
    if xerr != nil {
        return nullAhf, nullUd, fail.Wrap(xerr, "failed to get image")
    }
    if request.DiskSize > template.DiskSize {
        template.DiskSize = request.DiskSize
    } else if template.DiskSize == 0 {
        // Determines appropriate disk size
        switch {
        case template.Cores < 16:
            template.DiskSize = 100
        case template.Cores < 32:
            template.DiskSize = 200
        default:
            template.DiskSize = 400
        }
    }

    rim, xerr := s.GetImage(request.ImageID)
    if xerr != nil {
        return nullAhf, nullUd, xerr
    }

    logrus.Debugf("Selected template: '%s', '%s'", template.ID, template.Name)

    // Select usable availability zone, the first one in the list
    if s.GcpConfig.Zone == "" {
        azList, xerr := s.ListAvailabilityZones()
        if xerr != nil {
            return nullAhf, nullUd, xerr
        }
        var az string
        for az = range azList {
            break
        }
        s.GcpConfig.Zone = az
        logrus.Debugf("Selected Availability Zone: '%s'", az)
    }

    // Sets provider parameters to create ahf
    userDataPhase1, xerr := userData.Generate(userdata.PHASE1_INIT)
    if xerr != nil {
        return nullAhf, nullUd, xerr
    }

    // --- Initializes abstract.HostCore ---

    hostCore := abstract.NewHostCore()
    hostCore.PrivateKey = request.KeyPair.PrivateKey // Add PrivateKey to ahf definition
    hostCore.Password = request.Password

    // --- query provider for ahf creation ---

    logrus.Debugf("requesting host '%s' resource creation...", request.ResourceName)
    var desistError error

    // Retry creation until success, for 10 minutes
    retryErr := retry.WhileUnsuccessfulDelay5Seconds(
        func() error {
            var (
                innerErr error
                server   *abstract.HostCore
            )
            server, innerErr = buildGcpMachine(s.ComputeService, s.GcpConfig.ProjectID, request.ResourceName, rim.URL, s.GcpConfig.Region, s.GcpConfig.Zone, s.GcpConfig.NetworkName, defaultNetwork.Name, string(userDataPhase1), isGateway, template)
            if innerErr != nil {
                if server != nil {
                    // try deleting server
                    killErr := s.DeleteHost(server.ID)
                    if killErr != nil {
                        switch killErr.(type) {
                        case *fail.ErrTimeout:
                            logrus.Error("ErrTimeout cleaning up gcp instance")
                        default:
                            logrus.Errorf("Something else happened to gcp instance: %+v", killErr)
                        }
                        innerErr = fail.AddConsequence(innerErr, killErr)
                    }
                    return innerErr
                }

                if gerr, ok := innerErr.(*googleapi.Error); ok {
                    logrus.Warnf("Received GCP errorcode: %d", gerr.Code)

                    if !(gerr.Code == 200 || gerr.Code == 429 || gerr.Code == 500 || gerr.Code == 503) {
                        desistError = gerr
                        return nil
                    }
                }

                logrus.Warnf("error creating ahf: %+v", innerErr)
                return innerErr
            }

            if server == nil {
                return fail.NewError("failed to create server")
            }

            hostCore.ID = server.ID
            hostCore.Name = server.Name

            // Wait that Host is ready, not just that the build is started
            _, innerErr = s.WaitHostReady(ahf, temporal.GetLongOperationTimeout())
            if innerErr != nil {
                killErr := s.DeleteHost(hostCore.ID)
                if killErr != nil {
                    switch killErr.(type) {
                    case *fail.ErrTimeout:
                        logrus.Error("ErrTimeout cleaning up gcp instance")
                    default:
                        logrus.Errorf("Something else happened to gcp instance: %+v", killErr)
                    }
                    innerErr = fail.AddConsequence(innerErr, killErr)
                }
                return innerErr
            }
            return nil
        },
        temporal.GetLongOperationTimeout(),
    )
    if retryErr != nil {
        return nil, userData, retryErr
    }
    if desistError != nil {
        return nullAhf, nullUd, abstract.ResourceForbiddenError(request.ResourceName, fmt.Sprintf("error creating ahf: %s", desistError.Error()))
    }
    logrus.Debugf("ahf resource created.")

    newHost := abstract.NewHostFull()
    newHost.Core = hostCore
    newHost.Sizing = converters.HostTemplateToHostEffectiveSizing(*template)
    newHost.Network.IsGateway = isGateway
    newHost.Network.DefaultNetworkID = defaultNetworkID

    // Starting from here, delete host if exiting with error
    defer func() {
        if xerr != nil {
            logrus.Infof("Cleanup, deleting host '%s'", hostCore.Name)
            derr := s.DeleteHost(hostCore.ID)
            if derr != nil {
                switch derr.(type) {
                case *fail.ErrNotFound:
                    logrus.Errorf("Cleaning up on failure, failed to delete host '%s', resource not found: '%v'", hostCore.Name, derr)
                case *fail.ErrTimeout:
                    logrus.Errorf("Cleaning up on failure, failed to delete host '%s', timeout: '%v'", hostCore.Name, derr)
                default:
                    logrus.Errorf("Cleaning up on failure, failed to delete host '%s': '%v'", hostCore.Name, derr)
                }
                _ = xerr.AddConsequence(derr)
            }
        }
    }()

    if !newHost.OK() {
        logrus.Warnf("Missing data in ahf: %s", spew.Sdump(newHost))
    }

    return newHost, userData, nil
}

// WaitHostReady waits an host achieve ready state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return an utils.ErrInvalidParameter.
func (s *Stack) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (_ *abstract.HostCore, xerr fail.Error) {
    nullAhc := abstract.NewHostCore()
    if s == nil {
        return nullAhc, fail.InvalidInstanceError()
    }
    ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
    if xerr != nil {
        return nullAhc, xerr
    }

    tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.gcp"), "(%s)", hostRef).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

    retryErr := retry.WhileUnsuccessful(
        func() error {
            hostComplete, innerErr := s.InspectHost(ahf)
            if innerErr != nil {
                return innerErr
            }

            if hostComplete.Core.LastState != hoststate.STARTED {
                return fail.NotAvailableError("not in ready state (current state: %s)", hostComplete.Core.LastState.String())
            }
            return nil
        },
        temporal.GetDefaultDelay(),
        timeout,
    )
    if retryErr != nil {
        if _, ok := retryErr.(*retry.ErrTimeout); ok {
            return nullAhc, abstract.ResourceTimeoutError("host", ahf.GetName(), timeout)
        }
        return nullAhc, retryErr
    }
    return ahf.Core, nil
}

func publicAccess(isPublic bool) []*compute.AccessConfig {
    if isPublic {
        return []*compute.AccessConfig{
            {
                Type: "ONE_TO_ONE_NAT",
                Name: "External NAT",
            },
        }
    }

    return []*compute.AccessConfig{}
}

// buildGcpMachine ...
func buildGcpMachine(
    service *compute.Service,
    projectID string,
    instanceName string,
    imageID string,
    region string,
    zone string,
    network string,
    subnetwork string,
    userdata string,
    isPublic bool,
    template *abstract.HostTemplate,
) (*abstract.HostCore, fail.Error) {

    prefix := "https://www.googleapis.com/compute/v1/projects/" + projectID

    imageURL := imageID

    tag := "nat"
    if !isPublic {
        tag = fmt.Sprintf("no-ip-%s", subnetwork)
    }

    instance := &compute.Instance{
        Name:         instanceName,
        Description:  "compute sample instance",
        MachineType:  prefix + "/zones/" + zone + "/machineTypes/" + template.Name,
        CanIpForward: isPublic,
        Tags: &compute.Tags{
            Items: []string{tag},
        },
        Disks: []*compute.AttachedDisk{
            {
                AutoDelete: true,
                Boot:       true,
                Type:       "PERSISTENT",
                InitializeParams: &compute.AttachedDiskInitializeParams{
                    DiskName:    fmt.Sprintf("%s-disk", instanceName),
                    SourceImage: imageURL,
                    DiskSizeGb:  int64(template.DiskSize),
                },
            },
        },
        NetworkInterfaces: []*compute.NetworkInterface{
            {
                AccessConfigs: publicAccess(isPublic),
                Network:       prefix + "/global/networks/" + network,
                Subnetwork:    prefix + "/regions/" + region + "/subnetworks/" + subnetwork,
            },
        },
        ServiceAccounts: []*compute.ServiceAccount{
            {
                Email: "default",
                Scopes: []string{
                    compute.DevstorageFullControlScope,
                    compute.ComputeScope,
                },
            },
        },
        Metadata: &compute.Metadata{
            Items: []*compute.MetadataItems{
                {
                    Key:   "startup-script",
                    Value: &userdata,
                },
            },
        },
    }

    op, err := service.Instances.Insert(projectID, zone, instance).Do()
    if err != nil {
        return nil, fail.ToError(err)
    }

    etag := op.Header.Get("Etag")
    oco := OpContext{
        Operation:    op,
        ProjectID:    projectID,
        Service:      service,
        DesiredState: "DONE",
    }

    xerr := waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
    if xerr != nil {
        return nil, xerr
    }

    inst, err := service.Instances.Get(projectID, zone, instanceName).IfNoneMatch(etag).Do()
    if err != nil {
        return nil, fail.ToError(err)
    }

    logrus.Tracef("Got compute.Instance, err: %#v, %v", inst, err)

    if googleapi.IsNotModified(err) {
        logrus.Warnf("Instance not modified since insert.")
    }

    hostCore := abstract.NewHostCore()
    hostCore.ID = strconv.FormatUint(inst.Id, 10)
    hostCore.Name = inst.Name

    return hostCore, nil
}

// InspectHost returns the host identified by ref (name or id) or by a *abstract.HostFull containing an id
func (s *Stack) InspectHost(hostParam stacks.HostParameter) (host *abstract.HostFull, xerr fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }

    castedErr := xerr.(error)
    defer fail.OnPanic(&castedErr)

    hostComplete := abstract.NewHostFull()

    ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
    if xerr != nil {
        return nil, xerr
    }
    if ahf.Core.ID == "" {
        return nil, fail.InvalidParameterError("hostParam", "hostParam must be an ID as a string, or an *abstract.HostCore or an *abstract.HostFull")
    }

    gcpHost, err := s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, hostRef).Do()
    if err != nil {
        return nil, fail.ToError(err)
    }
    _ = &compute.Instance{}
    hostComplete.Core.LastState, err = stateConvert(gcpHost.Status)
    if err != nil {
        return nil, fail.ToError(err)
    }
    hostComplete.Core.Name = gcpHost.Hostname

    var subnets []IPInSubnet
    for _, nit := range gcpHost.NetworkInterfaces {
        snet := genURL(nit.Subnetwork)
        if !utils.IsEmpty(snet) {
            pubIP := ""
            for _, aco := range nit.AccessConfigs {
                if aco != nil {
                    if aco.NatIP != "" {
                        pubIP = aco.NatIP
                    }
                }
            }

            subnets = append(subnets, IPInSubnet{
                Subnet:   snet,
                IP:       nit.NetworkIP,
                PublicIP: pubIP,
            })
        }
    }

    var resouceNetworks []IPInSubnet
    for _, sn := range subnets {
        region, err := getRegionFromSelfLink(sn.Subnet)
        if err != nil {
            continue
        }
        psg, err := s.ComputeService.Subnetworks.Get(s.GcpConfig.ProjectID, region, getResourceNameFromSelfLink(sn.Subnet)).Do()
        if err != nil {
            continue
        }

        resouceNetworks = append(resouceNetworks, IPInSubnet{
            Subnet:   sn.Subnet,
            Name:     psg.Name,
            ID:       strconv.FormatUint(psg.Id, 10),
            IP:       sn.IP,
            PublicIP: sn.PublicIP,
        })
    }

    ip4bynetid := make(map[string]string)
    netnamebyid := make(map[string]string)
    netidbyname := make(map[string]string)

    ipv4 := ""
    for _, rn := range resouceNetworks {
        ip4bynetid[rn.ID] = rn.IP
        netnamebyid[rn.ID] = rn.Name
        netidbyname[rn.Name] = rn.ID
        if rn.PublicIP != "" {
            ipv4 = rn.PublicIP
        }
    }

    hostComplete.Network.IPv4Addresses = ip4bynetid
    hostComplete.Network.NetworksByID = netnamebyid
    hostComplete.Network.NetworksByName = netidbyname
    hostComplete.Network.PublicIPv4 = ipv4

    hostComplete.Sizing = fromMachineTypeToAllocatedSize(gcpHost.MachineType)

    // if !hostComplete.OK() {
    // 	logrus.Warnf("[TRACE] Unexpected host status: %s", spew.Sdump(host))
    // }

    return hostComplete, nil
}

func fromMachineTypeToAllocatedSize(machineType string) *abstract.HostEffectiveSizing {
    hz := abstract.HostEffectiveSizing{}

    // FIXME: Implement mapping

    return &hz
}

func stateConvert(gcpHostStatus string) (hoststate.Enum, fail.Error) {
    switch gcpHostStatus {
    case "PROVISIONING":
        return hoststate.STARTING, nil
    case "REPAIRING":
        return hoststate.ERROR, nil
    case "RUNNING":
        return hoststate.STARTED, nil
    case "STAGING":
        return hoststate.STARTING, nil
    case "STOPPED":
        return hoststate.STOPPED, nil
    case "STOPPING":
        return hoststate.STOPPING, nil
    case "SUSPENDED":
        return hoststate.STOPPED, nil
    case "SUSPENDING":
        return hoststate.STOPPING, nil
    case "TERMINATED":
        return hoststate.STOPPED, nil
    default:
        return -1, fail.NewError("unexpected host status: [%s]", gcpHostStatus)
    }
}

// GetHostByName returns the host identified by ref (name or id)
func (s *Stack) GetHostByName(name string) (*abstract.HostCore, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }
    if name == "" {
        return nil, fail.InvalidParameterError("name", "cannot be empty string")
    }

    hosts, xerr := s.ListHosts(false)
    if xerr != nil {
        return nil, xerr
    }

    for _, host := range hosts {
        if host.Core.Name == name {
            return host.Core, nil
        }
    }

    return nil, abstract.ResourceNotFoundError("host", name)
}

// DeleteHost deletes the host identified by id
func (s *Stack) DeleteHost(hostParam stacks.HostParameter) (xerr fail.Error) {
    if s == nil {
        return fail.InvalidInstanceError()
    }
    ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
    if xerr != nil {
        return xerr
    }

    service := s.ComputeService
    projectID := s.GcpConfig.ProjectID
    zone := s.GcpConfig.Zone

    _, err := service.Instances.Get(projectID, zone, ahf.Core.ID).Do()
    if err != nil {
        return fail.ToError(err)
    }

    op, err := service.Instances.Delete(projectID, zone, ahf.Core.ID).Do()
    if err != nil {
        return fail.ToError(err)
    }

    oco := OpContext{
        Operation:    op,
        ProjectID:    projectID,
        Service:      service,
        DesiredState: "DONE",
    }

    xerr = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostCleanupTimeout())
    // TODO: handle xerr value

    waitErr := retry.WhileUnsuccessfulDelay5Seconds(
        func() error {
            _, recErr := service.Instances.Get(projectID, zone, ahf.Core.ID).Do()
            if gerr, ok := recErr.(*googleapi.Error); ok {
                if gerr.Code == 404 {
                    return nil
                }
            }
            return fail.Wrap(recErr, "error waiting for host '%s' to disappear", hostRef)
        },
        temporal.GetContextTimeout(),
    )

    if waitErr != nil {
        logrus.Error(fail.RootCause(waitErr))
    }

    return xerr
}

// ResizeHost change the template used by an host
func (s *Stack) ResizeHost(hostParam stacks.HostParameter, request abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
    return nil, fail.NotImplementedError("ResizeHost() not implemented yet") // FIXME: Technical debt
}

// ListHosts lists available hosts
func (s *Stack) ListHosts(detailed bool) (_ abstract.HostList, xerr fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }

    var hostList abstract.HostList
    compuService := s.ComputeService
    token := ""
    for paginate := true; paginate; {
        resp, err := compuService.Instances.List(s.GcpConfig.ProjectID, s.GcpConfig.Zone).PageToken(token).Do()
        if err != nil {
            return hostList, fail.Wrap(err, "cannot list hosts")
        }
        for _, instance := range resp.Items {
            nhost := abstract.NewHostCore()
            nhost.ID = strconv.FormatUint(instance.Id, 10)
            nhost.Name = instance.Name
            nhost.LastState, _ = stateConvert(instance.Status)

            var hostFull *abstract.HostFull
            if detailed {
                hostFull, xerr = s.InspectHost(nhost)
                if xerr != nil {
                    return nil, xerr
                }
            } else {
                hostFull = abstract.NewHostFull()
                hostFull.Core.Replace(nhost)
            }

            // FIXME Populate host, what's missing ?
            hostList = append(hostList, hostFull)
        }
        token := resp.NextPageToken
        paginate = token != ""
    }

    return hostList, nil
}

// StopHost stops the host identified by id
func (s *Stack) StopHost(hostParam stacks.HostParameter) fail.Error {
    if s == nil {
        return fail.InvalidInstanceError()
    }
    ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
    if xerr != nil {
        return xerr
    }

    service := s.ComputeService

    op, err := service.Instances.Stop(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ahf.Core.ID).Do()
    if err != nil {
        return fail.ToError(err)
    }

    oco := OpContext{
        Operation:    op,
        ProjectID:    s.GcpConfig.ProjectID,
        Service:      service,
        DesiredState: "DONE",
    }

    return waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
}

// StartHost starts the host identified by id
func (s *Stack) StartHost(hostParam stacks.HostParameter) fail.Error {
    if s == nil {
        return fail.InvalidInstanceError()
    }
    ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
    if xerr != nil {
        return xerr
    }

    service := s.ComputeService

    op, err := service.Instances.Start(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ahf.Core.ID).Do()
    if err != nil {
        return fail.ToError(err)
    }

    oco := OpContext{
        Operation:    op,
        ProjectID:    s.GcpConfig.ProjectID,
        Service:      service,
        DesiredState: "DONE",
    }

    return waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
}

// RebootHost reboot the host identified by id
func (s *Stack) RebootHost(hostParam stacks.HostParameter) fail.Error {
    if s == nil {
        return fail.InvalidInstanceError()
    }
    ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
    if xerr != nil {
        return xerr
    }

    service := s.ComputeService

    op, err := service.Instances.Stop(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ahf.GetID()).Do()
    if err != nil {
        return fail.ToError(err)
    }

    oco := OpContext{
        Operation:    op,
        ProjectID:    s.GcpConfig.ProjectID,
        Service:      service,
        DesiredState: "DONE",
    }

    xerr = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
    if xerr != nil {
        return xerr
    }

    op, err = service.Instances.Start(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ahf.GetID()).Do()
    if err != nil {
        return fail.ToError(err)
    }

    oco = OpContext{
        Operation:    op,
        ProjectID:    s.GcpConfig.ProjectID,
        Service:      service,
        DesiredState: "DONE",
    }

    return waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
}

// GetHostState returns the host identified by id
func (s *Stack) GetHostState(hostParam stacks.HostParameter) (hoststate.Enum, fail.Error) {
    if s == nil {
        return hoststate.ERROR, fail.InvalidInstanceError()
    }

    host, xerr := s.InspectHost(hostParam)
    if xerr != nil {
        return hoststate.ERROR, xerr
    }

    return host.Core.LastState, nil
}

// -------------Provider Infos-------------------------------------------------------------------------------------------

// ListAvailabilityZones lists the usable AvailabilityZones
func (s *Stack) ListAvailabilityZones() (map[string]bool, fail.Error) {
    zones := make(map[string]bool)
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }

    resp, err := s.ComputeService.Zones.List(s.GcpConfig.ProjectID).Do()
    if err != nil {
        return zones, fail.ToError(err)
    }
    for _, region := range resp.Items {
        zones[region.Name] = region.Status == "UP"
    }

    return zones, nil
}

// ListRegions ...
func (s *Stack) ListRegions() ([]string, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }

    var regions []string

    compuService := s.ComputeService

    resp, err := compuService.Regions.List(s.GcpConfig.ProjectID).Do()
    if err != nil {
        return regions, fail.ToError(err)
    }
    for _, region := range resp.Items {
        regions = append(regions, region.Name)
    }

    return regions, nil
}
