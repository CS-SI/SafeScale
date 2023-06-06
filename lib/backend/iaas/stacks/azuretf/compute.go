/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package azuretf

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"strconv"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// -------------IMAGES---------------------------------------------------------------------------------------------------

// ListImages lists available OS images
func (s stack) ListImages(ctx context.Context, _ bool) (out []*abstract.Image, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	// FIXME: It has to be remade from scratch...

	var images []*abstract.Image
	// FIXME: Don't even add CentOS, our image selection algorithm is not able to select the right one, it has to be remade from scratch because it assumes that the the length of the full ID of an images is the same for all images, which is false for Azure; as a consequence, looking for "ubuntu" will return maybe a Centos, maybe something else...
	/*
		images = append(images, &abstract.Image{
			ID:          strings.Join([]string{"OpenLogic", "CentOS", "8_5-gen2"}, ":"),
			Name:        strings.Join([]string{"OpenLogic", "CentOS", "8_5-gen2"}, ":"),
			URL:         "",
			Description: "",
			StorageType: "",
			DiskSize:    0,
			Publisher:   "cognosys",
			Offer:       "centos-8-latest",
			Sku:         "centos-8-latest",
		})
	*/
	images = append(images, &abstract.Image{
		ID:          strings.Join([]string{"Canonical", "UbuntuServer", "18.04-LTS"}, ":"),
		Name:        strings.Join([]string{"Canonical", "UbuntuServer", "18.04-LTS"}, ":"),
		URL:         "",
		Description: "",
		StorageType: "",
		DiskSize:    30,
		Publisher:   "Canonical",
		Offer:       "UbuntuServer",
		Sku:         "18.04-LTS",
	})
	images = append(images, &abstract.Image{
		ID:          strings.Join([]string{"Canonical", "0001-com-ubuntu-minimal-focal", "minimal-20_04-lts"}, ":"),
		Name:        strings.Join([]string{"Canonical", "0001-com-ubuntu-minimal-focal", "minimal-20_04-lts"}, ":"),
		URL:         "",
		Description: "",
		StorageType: "",
		DiskSize:    30,
		Publisher:   "Canonical",
		Offer:       "0001-com-ubuntu-minimal-focal",
		Sku:         "minimal-20_04-lts",
	})
	images = append(images, &abstract.Image{
		ID:          strings.Join([]string{"Canonical", "0001-com-ubuntu-server-jammy", "22_04-lts-gen2"}, ":"),
		Name:        strings.Join([]string{"Canonical", "0001-com-ubuntu-server-jammy", "22_04-lts-gen2"}, ":"),
		URL:         "",
		Description: "",
		StorageType: "",
		DiskSize:    30,
		Publisher:   "Canonical",
		Offer:       "0001-com-ubuntu-server-jammy",
		Sku:         "22_04-lts-gen2",
	})

	return images, nil
}

// InspectImage returns the Image referenced by id
func (s stack) InspectImage(ctx context.Context, id string) (_ *abstract.Image, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	return nil, fail.NotImplementedError("implement me")
}

// -------------TEMPLATES------------------------------------------------------------------------------------------------

func ListAzureMachineTemplates(sid string, loc string) ([]*abstract.HostTemplate, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain a credential: %w", err)
	}

	ctx := context.Background()
	client, err := armcompute.NewResourceSKUsClient(sid, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	var answer []*abstract.HostTemplate
	templates := make(map[string]*abstract.HostTemplate)
	pager := client.NewListPager(&armcompute.ResourceSKUsClientListOptions{Filter: to.Ptr(fmt.Sprintf("location eq '%s'", loc)), IncludeExtendedLocations: nil})
	for pager.More() {
		nextResult, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to advance page: %w", err)
		}
		for _, v := range nextResult.Value {
			if v != nil {
				hot := &abstract.HostTemplate{}

				for _, capa := range v.Capabilities {
					if capa.Name != nil {
						if strings.Compare(*capa.Name, "vCPUs") == 0 {
							if capa.Value != nil {
								if s, err := strconv.ParseInt(*capa.Value, 10, 32); err != nil {
									continue
								} else {
									hot.Cores = int(s)
								}
							}
						}
						if strings.Compare(*capa.Name, "MemoryGB") == 0 {
							if capa.Value != nil {
								if s, err := strconv.ParseInt(*capa.Value, 10, 32); err != nil {
									continue
								} else {
									hot.RAMSize = float32(s)
								}
							}
						}
						if strings.Compare(*capa.Name, "MaxResourceVolumeMB") == 0 {
							if capa.Value != nil {
								if s, err := strconv.ParseInt(*capa.Value, 10, 32); err != nil {
									continue
								} else {
									hot.DiskSize = int(s / 1024)
								}
							}
						}
						if strings.Compare(*capa.Name, "GPUs") == 0 {
							if capa.Value != nil {
								if s, err := strconv.ParseInt(*capa.Value, 10, 32); err != nil {
									continue
								} else {
									hot.GPUNumber = int(s)
								}
							}
						}
						if strings.Compare(*capa.Name, "ACUs") == 0 {
							if capa.Value != nil {
								if s, err := strconv.ParseInt(*capa.Value, 10, 32); err != nil {
									continue
								} else {
									hot.CPUPerf = float32(s)
								}
							}
						}
					}
				}

				if strings.Compare(*v.ResourceType, "virtualMachines") != 0 {
					continue
				}

				hot.Name = *v.Name
				hot.ID = *v.Name

				templates[hot.ID] = hot
			}
		}
	}

	for _, v := range templates {
		answer = append(answer, v)
	}

	return answer, nil
}

// ListTemplates overload OpenStackGcp ListTemplate method to filter wind and flex instance and add GPU configuration
func (s stack) ListTemplates(ctx context.Context, _ bool) (_ []*abstract.HostTemplate, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	ao, err := s.GetRawAuthenticationOptions(ctx)
	if err != nil {
		return nil, fail.Wrap(err, "error getting authentication options")
	}

	templs, xerr := ListAzureMachineTemplates(ao.SubscriptionID, ao.Region)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "error listing templates")
	}

	return templs, nil
}

// InspectTemplate ...
func (s stack) InspectTemplate(ctx context.Context, id string) (_ *abstract.HostTemplate, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	return nil, fail.NotImplementedError("implement me")
}

// -------------SSH KEYS-------------------------------------------------------------------------------------------------

// CreateKeyPair FIXME: change code to really create a keypair on provider side
// CreateKeyPair creates and import a key pair
func (s stack) CreateKeyPair(ctx context.Context, name string) (_ *abstract.KeyPair, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	return abstract.NewKeyPair(name)
}

// InspectKeyPair returns the key pair identified by id
func (s stack) InspectKeyPair(ctx context.Context, id string) (*abstract.KeyPair, fail.Error) {
	return nil, fail.NotImplementedError("InspectKeyPair() not implemented yet") // FIXME: Technical debt
}

// ListKeyPairs lists available key pairs
func (s stack) ListKeyPairs(context.Context) ([]*abstract.KeyPair, fail.Error) {
	return nil, fail.NotImplementedError("ListKeyPairs() not implemented yet") // FIXME: Technical debt
}

// DeleteKeyPair deletes the key pair identified by id
func (s stack) DeleteKeyPair(ctx context.Context, id string) fail.Error {
	return fail.NotImplementedError("DeleteKeyPair() not implemented yet") // FIXME: Technical debt
}

// CreateHost creates a host meeting the requirements specified by request
func (s stack) CreateHost(ctx context.Context, request abstract.HostRequest, extra interface{}) (_ *abstract.HostFull, _ *userdata.Content, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	return nil, nil, fail.NotImplementedError("useless method")
}

// WaitHostReady waits until a host reaches ready state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return a utils.ErrInvalidParameter.
func (s stack) WaitHostReady(ctx context.Context, hostParam stacks.HostParameter, timeout time.Duration) (_ *abstract.HostCore, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			hostComplete, innerErr := s.InspectHost(ctx, ahf)
			if innerErr != nil {
				return innerErr
			}

			if hostComplete.CurrentState != hoststate.Started {
				return fail.NotAvailableError(
					"not in ready state (current state: %s)", hostComplete.CurrentState.String(),
				)
			}
			return nil
		},
		timings.NormalDelay(),
		timeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return nil, fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return nil, fail.Wrap(fail.Cause(retryErr), "timeout")
		default:
			return nil, retryErr
		}
	}

	return ahf.Core, nil
}

// ClearHostStartupScript clears the userdata startup script for Host instance (metadata service)
func (s stack) ClearHostStartupScript(ctx context.Context, hostParam stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	return fail.NotImplementedError("implement me")
}

func (s stack) ChangeSecurityGroupSecurity(ctx context.Context, b bool, b2 bool, net string, s2 string) fail.Error {
	return nil
}

// InspectHost returns the host identified by ref (name or id) or by a *abstract.HostFull containing an id
func (s stack) InspectHost(ctx context.Context, hostParam stacks.HostParameter) (host *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError("implement me")
}

// DeleteHost deletes the host identified by id
func (s stack) DeleteHost(ctx context.Context, hostParam stacks.HostParameter) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	return fail.NotImplementedError("implement me")
}

// ListHosts lists available hosts
func (s stack) ListHosts(ctx context.Context, detailed bool) (_ abstract.HostList, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NewError("useless method") // does not make sense with pure terraform drivers
}

// StopHost stops the host identified by id
func (s stack) StopHost(ctx context.Context, hostParam stacks.HostParameter, gracefully bool) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	return fail.NotImplementedError("implement me")
}

// StartHost starts the host identified by id
func (s stack) StartHost(ctx context.Context, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	return fail.NotImplementedError("implement me")
}

// RebootHost reboot the host identified by id
func (s stack) RebootHost(ctx context.Context, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	return fail.NotImplementedError("implement me")
}

func (s stack) GetHostState(ctx context.Context, hostParam stacks.HostParameter) (hoststate.Enum, fail.Error) {
	if valid.IsNil(s) {
		return hoststate.Error, fail.InvalidInstanceError()
	}

	host, xerr := s.InspectHost(ctx, hostParam)
	if xerr != nil {
		return hoststate.Error, xerr
	}

	return host.CurrentState, nil
}

// -------------Provider Infos-------------------------------------------------------------------------------------------

// ListAvailabilityZones lists the usable AvailabilityZones
func (s stack) ListAvailabilityZones(ctx context.Context) (_ map[string]bool, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError("implement me")
}

// ListRegions ...
func (s stack) ListRegions(ctx context.Context) (_ []string, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError("implement me")
}

// BindSecurityGroupToHost ...
func (s stack) BindSecurityGroupToHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	return fail.NotImplementedError("implement me")
}

// UnbindSecurityGroupFromHost unbinds a Security Group from a Host
func (s stack) UnbindSecurityGroupFromHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}

	return fail.NotImplementedError("implement me")
}
