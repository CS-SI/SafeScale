package operations

import (
	"bytes"
	"context"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/eko/gocache/v2/cache"
	"io"
	"regexp"
	"sync"
	"time"
)

type minService struct {
	loc objectstorage.Location
	aob abstract.ObjectStorageBucket
}

func (m minService) FilterImages(ctx context.Context, s string) ([]*abstract.Image, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) FindTemplateBySizing(ctx context.Context, requirements abstract.HostSizingRequirements) (*abstract.HostTemplate, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) FindTemplateByName(ctx context.Context, s string) (*abstract.HostTemplate, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) FindTemplateByID(ctx context.Context, s string) (*abstract.HostTemplate, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) GetProviderName() (string, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) GetMetadataBucket(ctx context.Context) (abstract.ObjectStorageBucket, fail.Error) {
	return m.aob, nil
}

func (m minService) GetMetadataKey() (*crypt.Key, fail.Error) {
	return nil, nil
}

func (m minService) GetCache(ctx context.Context) (cache.CacheInterface, fail.Error) {
	return nil, nil
}

func (m minService) InspectSecurityGroupByName(ctx context.Context, networkID string, name string) (*abstract.SecurityGroup, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListHostsWithTags(ctx context.Context, strings []string, m2 map[string]string) ([]*abstract.HostFull, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListTemplatesBySizing(ctx context.Context, requirements abstract.HostSizingRequirements, b bool) ([]*abstract.HostTemplate, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ObjectStorageConfiguration(ctx context.Context) (objectstorage.Config, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) SearchImage(ctx context.Context, s string) (*abstract.Image, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) TenantCleanup(ctx context.Context, b bool) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) GetLock(enum abstract.Enum) (*sync.Mutex, fail.Error) {
	return &sync.Mutex{}, nil
}

func (m minService) GetStackName() (string, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListAvailabilityZones(ctx context.Context) (map[string]bool, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListRegions(ctx context.Context) ([]string, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) InspectImage(ctx context.Context, id string) (*abstract.Image, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) InspectTemplate(ctx context.Context, id string) (*abstract.HostTemplate, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) CreateKeyPair(ctx context.Context, name string) (*abstract.KeyPair, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) InspectKeyPair(ctx context.Context, id string) (*abstract.KeyPair, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListKeyPairs(ctx context.Context) ([]*abstract.KeyPair, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) DeleteKeyPair(ctx context.Context, id string) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListSecurityGroups(ctx context.Context, networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) CreateSecurityGroup(ctx context.Context, networkRef, name, description string, rules abstract.SecurityGroupRules) (*abstract.SecurityGroup, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) InspectSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ClearSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) DeleteSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) AddRuleToSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {

	//TODO implement me
	panic("implement me")
}

func (m minService) DeleteRuleFromSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) GetDefaultSecurityGroupName(ctx context.Context) (string, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) EnableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) DisableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) InspectNetwork(ctx context.Context, id string) (*abstract.Network, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) InspectNetworkByName(ctx context.Context, name string) (*abstract.Network, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListNetworks(ctx context.Context) ([]*abstract.Network, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) DeleteNetwork(ctx context.Context, id string) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) HasDefaultNetwork(ctx context.Context) (bool, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) GetDefaultNetwork(ctx context.Context) (*abstract.Network, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (*abstract.Subnet, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) InspectSubnet(ctx context.Context, id string) (*abstract.Subnet, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) InspectSubnetByName(ctx context.Context, networkID, name string) (*abstract.Subnet, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListSubnets(ctx context.Context, networkID string) ([]*abstract.Subnet, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) DeleteSubnet(ctx context.Context, id string) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) CreateVIP(ctx context.Context, networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) AddPublicIPToVIP(ctx context.Context, ip *abstract.VirtualIP) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) BindHostToVIP(ctx context.Context, ip *abstract.VirtualIP, s string) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) UnbindHostFromVIP(ctx context.Context, ip *abstract.VirtualIP, s string) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) DeleteVIP(ctx context.Context, ip *abstract.VirtualIP) fail.Error {
	//TODO implement me
	panic("implement me")

}

func (m minService) CreateHost(ctx context.Context, request abstract.HostRequest, extra interface{}) (*abstract.HostFull, *userdata.Content, fail.Error) {
	//TODO implement me

	panic("implement me")
}

func (m minService) ClearHostStartupScript(ctx context.Context, parameter stacks.HostParameter) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) ChangeSecurityGroupSecurity(ctx context.Context, b bool, b2 bool, s string, s2 string) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) InspectHost(ctx context.Context, parameter stacks.HostParameter) (*abstract.HostFull, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) GetHostState(ctx context.Context, parameter stacks.HostParameter) (hoststate.Enum, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) GetTrueHostState(ctx context.Context, parameter stacks.HostParameter) (hoststate.Enum, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListHosts(ctx context.Context, b bool) (abstract.HostList, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) DeleteHost(ctx context.Context, parameter stacks.HostParameter) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) StopHost(ctx context.Context, host stacks.HostParameter, gracefully bool) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) StartHost(ctx context.Context, parameter stacks.HostParameter) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) RebootHost(ctx context.Context, parameter stacks.HostParameter) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) WaitHostReady(ctx context.Context, hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	//TODO implement me

	panic("implement me")
}

func (m minService) BindSecurityGroupToHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) UnbindSecurityGroupFromHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) InspectVolume(ctx context.Context, id string) (*abstract.Volume, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListVolumes(ctx context.Context) ([]*abstract.Volume, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) DeleteVolume(ctx context.Context, id string) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) InspectVolumeAttachment(ctx context.Context, serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListVolumeAttachments(ctx context.Context, serverID string) ([]*abstract.VolumeAttachment, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) DeleteVolumeAttachment(ctx context.Context, serverID, id string) fail.Error {
	//TODO implement me
	panic("implement me")
}

var MINTIMINGS = &temporal.MutableTimings{
	Timeouts: temporal.Timeouts{
		Communication:          100 * time.Millisecond,
		Connection:             100 * time.Millisecond,
		Context:                100 * time.Millisecond,
		HostCreation:           4 * time.Second, // 100ms too fast for concurrency, makes break clustertasks
		HostCleanup:            100 * time.Millisecond,
		HostOperation:          100 * time.Millisecond,
		HostLongOperation:      100 * time.Millisecond,
		Operation:              100 * time.Millisecond,
		Metadata:               100 * time.Millisecond,
		MetadataReadAfterWrite: 100 * time.Millisecond,
		SSHConnection:          100 * time.Millisecond,
		RebootTimeout:          100 * time.Millisecond,
	},
	Delays: temporal.Delays{
		Small:  100 * time.Millisecond,
		Normal: 100 * time.Millisecond,
		Big:    100 * time.Millisecond,
	},
}

func (m minService) Timings() (temporal.Timings, fail.Error) {
	return MINTIMINGS, nil
}

func (m minService) ListTags(ctx context.Context, kind abstract.Enum, id string) (map[string]string, fail.Error) {
	panic("implement me")
}

func (m minService) UpdateTags(ctx context.Context, kind abstract.Enum, id string, lmap map[string]string) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) DeleteTags(ctx context.Context, kind abstract.Enum, id string, keys []string) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) Build(m2 map[string]interface{}) (providers.Provider, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) GetAuthenticationOptions(ctx context.Context) (providers.Config, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) GetConfigurationOptions(ctx context.Context) (providers.Config, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) GetName() (string, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) GetStack() (api.Stack, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) GetCapabilities(ctx context.Context) (providers.Capabilities, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) GetTenantParameters() (map[string]interface{}, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) LookupRuleInSecurityGroup(ctx context.Context, group *abstract.SecurityGroup, rule *abstract.SecurityGroupRule) (bool, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) Protocol() (string, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) Configuration() (objectstorage.Config, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListBuckets(ctx context.Context, s string) ([]string, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) FindBucket(ctx context.Context, s string) (bool, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) InspectBucket(ctx context.Context, s string) (abstract.ObjectStorageBucket, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) CreateBucket(ctx context.Context, s string) (abstract.ObjectStorageBucket, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) DeleteBucket(ctx context.Context, s string) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) DownloadBucket(ctx context.Context, bucketName, decryptionKey string) ([]byte, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) UploadBucket(ctx context.Context, bucketName, localDirectory string) (ferr fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) ClearBucket(ctx context.Context, s string, s2 string, s3 string) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) ListObjects(ctx context.Context, s string, s2 string, s3 string) ([]string, fail.Error) {
	return m.loc.ListObjects(ctx, s, s2, s3)
}

func (m minService) InvalidateObject(ctx context.Context, s string, s2 string) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (m minService) InspectObject(ctx context.Context, s string, s2 string) (abstract.ObjectStorageItem, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (m minService) HasObject(ctx context.Context, s string, s2 string) (bool, fail.Error) {
	return m.loc.HasObject(ctx, s, s2)
}

func (m minService) ReadObject(ctx context.Context, s string, s2 string, writer io.Writer, i int64, i2 int64) (bytes.Buffer, fail.Error) {
	return m.loc.ReadObject(ctx, s, s2, writer, i, i2)
}

func (m minService) WriteMultiPartObject(ctx context.Context, s string, s2 string, reader io.Reader, i int64, i2 int, metadata abstract.ObjectStorageItemMetadata) (abstract.ObjectStorageItem, fail.Error) {
	return m.loc.WriteMultiPartObject(ctx, s, s2, reader, i, i2, metadata)
}

func (m minService) WriteObject(ctx context.Context, s string, s2 string, reader io.Reader, i int64, metadata abstract.ObjectStorageItemMetadata) (abstract.ObjectStorageItem, fail.Error) {
	return m.loc.WriteObject(ctx, s, s2, reader, i, metadata)
}

func (m minService) DeleteObject(ctx context.Context, s string, s2 string) fail.Error {
	return m.loc.DeleteObject(ctx, s, s2)
}

func (m minService) ItemEtag(ctx context.Context, s string, s2 string) (string, fail.Error) {
	//TODO implement me
	panic("implement me")
}
