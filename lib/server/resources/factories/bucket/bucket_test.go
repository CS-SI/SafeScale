/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package bucket

import (
	"io"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/v21/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/temporal"
	"github.com/stretchr/testify/require"
)

type FakeService struct {
	iaas.Service
	//providers.Provider
	//api.Stack
	//objectstorage.Location
	Do_ListBuckets []string
}

//iaas.Service
func (e *FakeService) CreateHostWithKeyPair(a abstract.HostRequest) (*abstract.HostFull, *userdata.Content, *abstract.KeyPair, fail.Error) {
	return nil, nil, nil, fail.NotImplementedError("fake")
}
func (e *FakeService) FilterImages(a string) ([]abstract.Image, fail.Error) {
	return []abstract.Image{}, fail.NotImplementedError("fake")
}
func (e *FakeService) FindTemplateByName(a string) (*abstract.HostTemplate, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) GetProviderName() (string, fail.Error) {
	return "Fake", nil
}
func (e *FakeService) GetMetadataBucket() (abstract.ObjectStorageBucket, fail.Error) {
	return abstract.ObjectStorageBucket{}, fail.NotImplementedError("fake")
}
func (e *FakeService) GetMetadataKey() (*crypt.Key, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) InspectHostByName(a string) (*abstract.HostFull, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) InspectSecurityGroupByName(networkID string, name string) (*abstract.SecurityGroup, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) ListHostsByName(a bool) (map[string]*abstract.HostFull, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) ListTemplatesBySizing(a abstract.HostSizingRequirements, b bool) ([]*abstract.HostTemplate, fail.Error) {
	return []*abstract.HostTemplate{}, fail.NotImplementedError("fake")
}
func (e *FakeService) SearchImage(a string) (*abstract.Image, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) TenantCleanup(a bool) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) WaitHostState(a string, b hoststate.Enum, c time.Duration) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) WaitVolumeState(a string, b volumestate.Enum, c time.Duration) (*abstract.Volume, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) GetCache(a string) (*iaas.ResourceCache, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) LookupRuleInSecurityGroup(a *abstract.SecurityGroup, b *abstract.SecurityGroupRule) (bool, fail.Error) {
	return false, fail.NotImplementedError("fake")
}

//providers.Provider
func (e *FakeService) Build(map[string]interface{}) (providers.Provider, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) ListImages(all bool) ([]abstract.Image, fail.Error) {
	return []abstract.Image{}, fail.NotImplementedError("fake")
}
func (e *FakeService) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
	return []abstract.HostTemplate{}, fail.NotImplementedError("fake")
}
func (e *FakeService) GetAuthenticationOptions() (providers.Config, fail.Error) {
	return providers.ConfigMap{}, fail.NotImplementedError("fake")
}
func (e *FakeService) GetConfigurationOptions() (providers.Config, fail.Error) {
	return providers.ConfigMap{}, fail.NotImplementedError("fake")
}
func (e *FakeService) GetName() (string, fail.Error) {
	return "Fake", nil
}
func (e *FakeService) GetStack() (api.Stack, fail.Error) {
	return api.StackProxy{}, fail.NotImplementedError("fake")
}
func (e *FakeService) GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error) {
	return []*regexp.Regexp{}, fail.NotImplementedError("fake")
}
func (e *FakeService) GetCapabilities() (providers.Capabilities, fail.Error) {
	return providers.Capabilities{}, fail.NotImplementedError("fake")
}
func (e *FakeService) GetTenantParameters() (map[string]interface{}, fail.Error) {
	return map[string]interface{}{}, fail.NotImplementedError("fake")
}

//api.Stack
func (e *FakeService) GetStackName() (string, fail.Error) {
	return "Fake", nil
}
func (e *FakeService) ListAvailabilityZones() (map[string]bool, fail.Error) {
	return map[string]bool{}, fail.NotImplementedError("fake")
}
func (e *FakeService) ListRegions() ([]string, fail.Error) {
	return []string{}, fail.NotImplementedError("fake")
}
func (e *FakeService) InspectImage(id string) (abstract.Image, fail.Error) {
	return abstract.Image{}, fail.NotImplementedError("fake")
}
func (e *FakeService) InspectTemplate(id string) (abstract.HostTemplate, fail.Error) {
	return abstract.HostTemplate{}, fail.NotImplementedError("fake")
}
func (e *FakeService) CreateKeyPair(name string) (*abstract.KeyPair, fail.Error) {
	return &abstract.KeyPair{}, fail.NotImplementedError("fake")
}
func (e *FakeService) InspectKeyPair(id string) (*abstract.KeyPair, fail.Error) {
	return &abstract.KeyPair{}, fail.NotImplementedError("fake")
}
func (e *FakeService) ListKeyPairs() ([]abstract.KeyPair, fail.Error) {
	return []abstract.KeyPair{}, fail.NotImplementedError("fake")
}
func (e *FakeService) DeleteKeyPair(id string) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) ListSecurityGroups(networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
	return []*abstract.SecurityGroup{}, fail.NotImplementedError("fake")
}
func (e *FakeService) CreateSecurityGroup(networkRef, name, description string, rules abstract.SecurityGroupRules) (*abstract.SecurityGroup, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) InspectSecurityGroup(sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) ClearSecurityGroup(sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) DeleteSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) AddRuleToSecurityGroup(sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) DeleteRuleFromSecurityGroup(sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) GetDefaultSecurityGroupName() (string, fail.Error) {
	return "", fail.NotImplementedError("fake")
}
func (e *FakeService) EnableSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) DisableSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) InspectNetwork(id string) (*abstract.Network, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) InspectNetworkByName(name string) (*abstract.Network, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) ListNetworks() ([]*abstract.Network, fail.Error) {
	return []*abstract.Network{}, fail.NotImplementedError("fake")
}
func (e *FakeService) DeleteNetwork(id string) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) HasDefaultNetwork() (bool, fail.Error) {
	return false, fail.NotImplementedError("fake")
}
func (e *FakeService) GetDefaultNetwork() (*abstract.Network, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) CreateSubnet(req abstract.SubnetRequest) (*abstract.Subnet, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) InspectSubnet(id string) (*abstract.Subnet, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) InspectSubnetByName(networkID, name string) (*abstract.Subnet, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) ListSubnets(networkID string) ([]*abstract.Subnet, fail.Error) {
	return []*abstract.Subnet{}, fail.NotImplementedError("fake")
}
func (e *FakeService) DeleteSubnet(id string) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) BindSecurityGroupToSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) UnbindSecurityGroupFromSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) CreateVIP(networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) AddPublicIPToVIP(*abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) BindHostToVIP(*abstract.VirtualIP, string) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) UnbindHostFromVIP(*abstract.VirtualIP, string) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) DeleteVIP(*abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) CreateHost(request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, fail.Error) {
	return nil, nil, fail.NotImplementedError("fake")
}
func (e *FakeService) ClearHostStartupScript(stacks.HostParameter) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) InspectHost(stacks.HostParameter) (*abstract.HostFull, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) GetHostState(stacks.HostParameter) (hoststate.Enum, fail.Error) {
	return hoststate.Enum(0), fail.NotImplementedError("fake")
}
func (e *FakeService) ListHosts(bool) (abstract.HostList, fail.Error) {
	return abstract.HostList{}, fail.NotImplementedError("fake")
}
func (e *FakeService) DeleteHost(stacks.HostParameter) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) StopHost(host stacks.HostParameter, gracefully bool) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) StartHost(stacks.HostParameter) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) RebootHost(stacks.HostParameter) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) ResizeHost(stacks.HostParameter, abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) InspectVolume(id string) (*abstract.Volume, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) ListVolumes() ([]abstract.Volume, fail.Error) {
	return []abstract.Volume{}, fail.NotImplementedError("fake")
}
func (e *FakeService) DeleteVolume(id string) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	return "", fail.NotImplementedError("fake")
}
func (e *FakeService) InspectVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	return nil, fail.NotImplementedError("fake")
}
func (e *FakeService) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Error) {
	return []abstract.VolumeAttachment{}, fail.NotImplementedError("fake")
}
func (e *FakeService) DeleteVolumeAttachment(serverID, id string) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) Migrate(operation string, params map[string]interface{}) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) Timings() (temporal.Timings, fail.Error) {
	var v temporal.Timings
	return v, fail.NotImplementedError("fake")
}

//objectstorage.Location
func (e *FakeService) Protocol() (string, fail.Error) {
	return "", fail.NotImplementedError("fake")
}
func (e *FakeService) Configuration() (objectstorage.Config, fail.Error) {
	return objectstorage.Config{}, fail.NotImplementedError("fake")
}
func (e *FakeService) ListBuckets(string) ([]string, fail.Error) {
	return e.Do_ListBuckets, nil
}
func (e *FakeService) FindBucket(string) (bool, fail.Error) {
	return false, fail.NotImplementedError("fake")
}
func (e *FakeService) InspectBucket(string) (abstract.ObjectStorageBucket, fail.Error) {
	return abstract.ObjectStorageBucket{}, fail.NotImplementedError("fake")
}
func (e *FakeService) CreateBucket(string) (abstract.ObjectStorageBucket, fail.Error) {
	return abstract.ObjectStorageBucket{}, fail.NotImplementedError("fake")
}
func (e *FakeService) DeleteBucket(string) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) ClearBucket(string, string, string) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) ListObjects(string, string, string) ([]string, fail.Error) {
	return []string{}, fail.NotImplementedError("fake")
}
func (e *FakeService) InspectObject(string, string) (abstract.ObjectStorageItem, fail.Error) {
	return abstract.ObjectStorageItem{}, fail.NotImplementedError("fake")
}
func (e *FakeService) ReadObject(string, string, io.Writer, int64, int64) fail.Error {
	return fail.NotImplementedError("fake")
}
func (e *FakeService) WriteMultiPartObject(string, string, io.Reader, int64, int, abstract.ObjectStorageItemMetadata) (abstract.ObjectStorageItem, fail.Error) {
	return abstract.ObjectStorageItem{}, fail.NotImplementedError("fake")
}
func (e *FakeService) WriteObject(string, string, io.Reader, int64, abstract.ObjectStorageItemMetadata) (abstract.ObjectStorageItem, fail.Error) {
	return abstract.ObjectStorageItem{}, fail.NotImplementedError("fake")
}
func (e *FakeService) DeleteObject(string, string) fail.Error {
	return fail.NotImplementedError("fake")
}

func TestService_List(t *testing.T) {

	var (
		svc  iaas.Service = nil
		list []string
		err  fail.Error
	)
	_, err = List(svc)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")

	svc = &FakeService{
		Do_ListBuckets: []string{},
	}
	list, err = List(svc)
	require.EqualValues(t, len(list), 0)
	require.EqualValues(t, err, nil)

	svc = &FakeService{
		Do_ListBuckets: []string{"BucketA"},
	}
	list, err = List(svc)
	require.EqualValues(t, len(list), 1)
	require.EqualValues(t, list[0], "BucketA")
	require.EqualValues(t, err, nil)

}

func TestService_New(t *testing.T) {

	/*
		var (
			svc  iaas.Service
			bucket resources.Bucket
			err  fail.Error
		)
	*/

}
