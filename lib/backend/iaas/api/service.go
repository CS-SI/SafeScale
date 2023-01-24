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

package iaasapi

import (
	"context"
	"time"

	"github.com/eko/gocache/v2/cache"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -o mocks/mock_service.go -i github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api.Service

// Service consolidates Provider and ObjectStorage.Location interfaces in a single interface
// completed with higher-level methods
type Service interface {
	FilterImages(context.Context, string) ([]*abstract.Image, fail.Error)
	FindTemplateBySizing(context.Context, abstract.HostSizingRequirements) (*abstract.HostTemplate, fail.Error)
	FindTemplateByName(context.Context, string) (*abstract.HostTemplate, fail.Error)
	FindTemplateByID(context.Context, string) (*abstract.HostTemplate, fail.Error)
	ProviderName() (string, fail.Error)
	ProviderDriver() (Provider, fail.Error)
	MetadataBucket(ctx context.Context) (*abstract.Bucket, fail.Error)
	MetadataKey() (*crypt.Key, fail.Error)
	Cache(context.Context) (cache.CacheInterface, fail.Error)
	InspectSecurityGroupByName(ctx context.Context, networkID string, name string) (*abstract.SecurityGroup, fail.Error)
	ListHostsByName(context.Context, bool) (map[string]*abstract.HostFull, fail.Error)
	ListTemplatesBySizing(context.Context, abstract.HostSizingRequirements, bool) ([]*abstract.HostTemplate, fail.Error)
	ObjectStorageConfiguration(ctx context.Context) (objectstorage.Config, fail.Error)
	SearchImage(context.Context, string) (*abstract.Image, fail.Error)
	TenantCleanup(context.Context, bool) fail.Error // cleans up the data relative to SafeScale from tenant (not implemented yet)
	WaitHostState(context.Context, string, hoststate.Enum, time.Duration) fail.Error
	WaitVolumeState(context.Context, string, volumestate.Enum, time.Duration) (*abstract.Volume, fail.Error)

	LookupRuleInSecurityGroup(context.Context, *abstract.SecurityGroup, *abstract.SecurityGroupRule) (bool, fail.Error)

	Provider

	// Location --- from interface objectstorage.Location ---
	objectstorage.Location
}
