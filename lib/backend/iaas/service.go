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

package iaas

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/eko/gocache/v2/cache"
	"github.com/gofrs/uuid"
	"github.com/oscarpicas/scribble"
	"github.com/oscarpicas/smetrics"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	imagefilters "github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract/filters/images"
	templatefilters "github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract/filters/templates"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

//go:generate minimock -o mocks/mock_service.go -i github.com/CS-SI/SafeScale/v22/lib/backend/iaas.Service

// Service consolidates Provider and ObjectStorage.Location interfaces in a single interface
// completed with higher-level methods
type Service interface {
	FilterImages(context.Context, string) ([]*abstract.Image, fail.Error)
	FindTemplateBySizing(context.Context, abstract.HostSizingRequirements) (*abstract.HostTemplate, fail.Error)
	FindTemplateByName(context.Context, string) (*abstract.HostTemplate, fail.Error)
	FindTemplateByID(context.Context, string) (*abstract.HostTemplate, fail.Error)
	GetProviderName() (string, fail.Error)
	GetMetadataBucket(ctx context.Context) (abstract.ObjectStorageBucket, fail.Error)
	GetMetadataKey() (*crypt.Key, fail.Error)
	GetCache(context.Context) (cache.CacheInterface, fail.Error)
	InspectSecurityGroupByName(ctx context.Context, networkID string, name string) (*abstract.SecurityGroup, fail.Error)
	ListHostsWithTags(context.Context, []string, map[string]string) ([]*abstract.HostFull, fail.Error)
	ListTemplatesBySizing(context.Context, abstract.HostSizingRequirements, bool) ([]*abstract.HostTemplate, fail.Error)
	ObjectStorageConfiguration(ctx context.Context) (objectstorage.Config, fail.Error)
	SearchImage(context.Context, string) (*abstract.Image, fail.Error)
	TenantCleanup(context.Context, bool) fail.Error // cleans up the data relative to SafeScale from tenant (not implemented yet)

	GetLock(abstract.Enum) (*sync.Mutex, fail.Error)

	// Provider --- from interface iaas.Providers ---
	providers.Provider

	LookupRuleInSecurityGroup(context.Context, *abstract.SecurityGroup, *abstract.SecurityGroupRule) (bool, fail.Error)

	// Location --- from interface objectstorage.Location ---
	objectstorage.Location
}

type Loader interface {
	LoadHost(inctx context.Context, svc Service, ref string) (interface{}, fail.Error)
	LoadCluster(inctx context.Context, svc Service, ref string) (interface{}, fail.Error)
	LoadLabel(inctx context.Context, svc Service, ref string) (interface{}, fail.Error)
	LoadNetwork(inctx context.Context, svc Service, ref string) (interface{}, fail.Error)
	LoadShare(inctx context.Context, svc Service, ref string) (interface{}, fail.Error)
	LoadVolume(inctx context.Context, svc Service, ref string) (interface{}, fail.Error)
	LoadBucket(inctx context.Context, svc Service, ref string) (interface{}, fail.Error)
	LoadSubnet(inctx context.Context, svc Service, netref string, ref string) (interface{}, fail.Error)
	LoadSecurityGroup(inctx context.Context, svc Service, ref string) (interface{}, fail.Error)
}

// service is the implementation struct of interface Service
type service struct {
	providers.Provider
	objectstorage.Location

	tenantName string

	cacheManager *wrappedCache

	metadataBucket abstract.ObjectStorageBucket
	metadataKey    *crypt.Key

	whitelistTemplateREs []*regexp.Regexp
	blacklistTemplateREs []*regexp.Regexp
	whitelistImageREs    []*regexp.Regexp
	blacklistImageREs    []*regexp.Regexp

	// this is a hack to avoid race conditions calling the Load* functions
	// the Load* global functions were a bad idea
	mLoadHost          *sync.Mutex
	mLoadCluster       *sync.Mutex
	mLoadLabel         *sync.Mutex
	mLoadNetwork       *sync.Mutex
	mLoadShare         *sync.Mutex
	mLoadVolume        *sync.Mutex
	mLoadBucket        *sync.Mutex
	mLoadSubnet        *sync.Mutex
	mLoadSecurityGroup *sync.Mutex
	mLoadFeature       *sync.Mutex
}

const (
	// CoreDRFWeight is the Dominant Resource Fairness weight of a core
	CoreDRFWeight float32 = 1.0
	// RAMDRFWeight is the Dominant Resource Fairness weight of 1 GB of RAM
	RAMDRFWeight float32 = 1.0 / 8.0
	// DiskDRFWeight is the Dominant Resource Fairness weight of 1 GB of Disk
	DiskDRFWeight float32 = 1.0 / 16.0
)

// NullService creates a service instance corresponding to null value
func NullService() *service { // nolint
	return nil
}

// IsNull tells if the instance is null value
func (instance *service) IsNull() bool {
	return instance == nil || instance.Provider == nil
}

// GetProviderName ...
func (instance service) GetProviderName() (string, fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	svcName, xerr := instance.Provider.GetName()
	if xerr != nil {
		return "", xerr
	}
	return svcName, nil
}

// GetName ...
// Satisfies interface data.Identifiable
func (instance service) GetName() (string, fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InconsistentError()
	}

	return instance.tenantName, nil
}

func (instance service) GetLock(en abstract.Enum) (*sync.Mutex, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InconsistentError()
	}

	switch en {
	case abstract.ClusterResource:
		return instance.mLoadCluster, nil
	case abstract.HostResource:
		return instance.mLoadHost, nil
	case abstract.LabelResource:
		return instance.mLoadLabel, nil
	case abstract.NetworkResource:
		return instance.mLoadNetwork, nil
	case abstract.SecurityGroupResource:
		return instance.mLoadSecurityGroup, nil
	case abstract.SubnetResource:
		return instance.mLoadSubnet, nil
	case abstract.VolumeResource:
		return instance.mLoadVolume, nil
	case abstract.ShareResource:
		return instance.mLoadShare, nil
	case abstract.ObjectStorageBucketResource:
		return instance.mLoadBucket, nil
	case abstract.FeatureResource:
		return instance.mLoadFeature, nil
	default:
		return nil, fail.InvalidParameterError("en", "wrong enumeration")
	}
}

// GetMetadataBucket returns the bucket instance describing metadata bucket
func (instance service) GetMetadataBucket(ctx context.Context) (abstract.ObjectStorageBucket, fail.Error) {
	if valid.IsNil(instance) {
		return abstract.ObjectStorageBucket{}, fail.InvalidInstanceError()
	}
	return instance.metadataBucket, nil
}

// GetMetadataKey returns the key used to crypt data in metadata bucket
func (instance service) GetMetadataKey() (*crypt.Key, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if instance.metadataKey == nil {
		return nil, fail.NotFoundError("no crypt key defined for metadata content")
	}
	return instance.metadataKey, nil
}

// ChangeProvider allows changing provider interface of service object (mainly for test purposes)
func (instance *service) ChangeProvider(provider providers.Provider) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if provider == nil {
		return fail.InvalidParameterCannotBeNilError("provider")
	}
	instance.Provider = provider
	return nil
}

// WaitVolumeState waits until a volume achieves state
// If timeout is reached, returns utils.ErrTimeout
func (instance service) WaitVolumeState(inctx context.Context, volumeID string, state volumestate.Enum, timeout time.Duration) (*abstract.Volume, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if volumeID == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("volumeID")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *abstract.Volume
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		for {
			v, err := instance.InspectVolume(ctx, volumeID)
			if err != nil {
				chRes <- result{nil, err}
				return
			}
			if v.State == state {
				chRes <- result{v, nil}
				return
			}

			// if all implementations of InspectVolume handle ctx correctly (they check if ctx is Done) this is not necessary...
			// but not all InspecVolume implementation does, so...
			breakIt := false
			select {
			case <-ctx.Done():
				breakIt = true
			default:
			}

			if breakIt {
				break
			}
		}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	case <-time.After(timeout):
		return nil, fail.TimeoutError(nil, timeout, "Wait host state timeout")
	}
}

// ListTemplates lists available host templates, if all bool is true, all templates are returned, if not, templates are filtered using blacklists and whitelists
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (instance service) ListTemplates(inctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  []*abstract.HostTemplate
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		allTemplates, err := instance.Provider.ListTemplates(ctx, all)
		if err != nil {
			chRes <- result{nil, err}
			return
		}

		if all {
			chRes <- result{allTemplates, nil}
			return
		}

		chRes <- result{instance.reduceTemplates(allTemplates, instance.whitelistTemplateREs, instance.blacklistTemplateREs), nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// FindTemplateByName returns the template by its name
func (instance service) FindTemplateByName(inctx context.Context, name string) (*abstract.HostTemplate, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *abstract.HostTemplate
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		allTemplates, err := instance.Provider.ListTemplates(ctx, true)
		if err != nil {
			chRes <- result{nil, err}
			return
		}
		for _, i := range allTemplates {
			i := i
			if i.Name == name {
				chRes <- result{i, nil}
				return
			}
		}
		chRes <- result{nil, fail.NotFoundError(fmt.Sprintf("template named '%s' not found", name))}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// FindTemplateByID returns the template by its ID
func (instance service) FindTemplateByID(ctx context.Context, id string) (*abstract.HostTemplate, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	allTemplates, err := instance.Provider.ListTemplates(ctx, true)
	if err != nil {
		return nil, err
	}
	for _, i := range allTemplates {
		i := i
		if i.ID == id {
			return i, nil
		}
	}
	return nil, fail.NotFoundError(fmt.Sprintf("template with id '%s' not found", id))
}

// FindTemplateBySizing returns an abstracted template corresponding to the Host Sizing Requirements
func (instance service) FindTemplateBySizing(inctx context.Context, sizing abstract.HostSizingRequirements) (*abstract.HostTemplate, fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *abstract.HostTemplate
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		useScannerDB := sizing.MinGPU > 0 || sizing.MinCPUFreq > 0

		// if we want a specific template and there is a match, we take it
		if sizing.Template != "" {
			// if match by name, we take it
			if ft, xerr := instance.FindTemplateByName(ctx, sizing.Template); xerr == nil {
				chRes <- result{ft, nil}
				return
			}

			// match by ID is also valid
			if ft, xerr := instance.FindTemplateByID(ctx, sizing.Template); xerr == nil {
				chRes <- result{ft, nil}
				return
			}

			// if we reached this point with a template in mind, it means that was not available, so we issue a warning about it
			logrus.WithContext(ctx).Warnf("template %s not found", sizing.Template)
		}

		templates, xerr := instance.ListTemplatesBySizing(ctx, sizing, useScannerDB)
		if xerr != nil {
			chRes <- result{nil, fail.Wrap(xerr, "failed to find template corresponding to requested resources")}
			return
		}

		var template *abstract.HostTemplate
		if len(templates) > 0 {
			template = templates[0]
			msg := fmt.Sprintf(
				"Selected host template: '%s' (%d core%s", template.Name, template.Cores,
				strprocess.Plural(uint(template.Cores)),
			)
			if template.CPUFreq > 0 {
				msg += fmt.Sprintf(" at %.01f GHz", template.CPUFreq)
			}
			msg += fmt.Sprintf(", %.01f GB RAM, %d GB disk", template.RAMSize, template.DiskSize)
			if template.GPUNumber > 0 {
				msg += fmt.Sprintf(", %d GPU%s", template.GPUNumber, strprocess.Plural(uint(template.GPUNumber)))
				if template.GPUType != "" {
					msg += fmt.Sprintf(" %s", template.GPUType)
				}
			}
			msg += ")"
			logrus.WithContext(ctx).Infof(msg)
		} else {
			logrus.WithContext(ctx).Errorf("failed to find template corresponding to requested resources")
			chRes <- result{nil, fail.Wrap(xerr, "failed to find template corresponding to requested resources")}
			return
		}
		chRes <- result{template, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// reduceTemplates filters from template slice the entries satisfying whitelist and blacklist regexps
func (instance service) reduceTemplates(
	tpls []*abstract.HostTemplate, whitelistREs, blacklistREs []*regexp.Regexp,
) []*abstract.HostTemplate {
	var finalFilter *templatefilters.Filter
	if len(whitelistREs) > 0 {
		// finalFilter = templatefilters.NewFilter(filterTemplatesByRegexSlice(instance.whitelistTemplateREs))
		finalFilter = templatefilters.NewFilter(filterTemplatesByRegexSlice(whitelistREs))
	}
	if len(blacklistREs) > 0 {
		//		blackFilter := templatefilters.NewFilter(filterTemplatesByRegexSlice(instance.blacklistTemplateREs))
		blackFilter := templatefilters.NewFilter(filterTemplatesByRegexSlice(blacklistREs))
		if finalFilter == nil {
			finalFilter = blackFilter.Not()
		} else {
			finalFilter = finalFilter.And(blackFilter.Not())
		}
	}
	if finalFilter != nil {
		return templatefilters.FilterTemplates(tpls, finalFilter)
	}
	return tpls
}

func filterTemplatesByRegexSlice(res []*regexp.Regexp) templatefilters.Predicate {
	return func(tpl *abstract.HostTemplate) bool {
		for _, re := range res {
			if re.Match([]byte(tpl.Name)) {
				return true
			}
		}
		return false
	}
}

// ListTemplatesBySizing select templates satisfying sizing requirements
// returned list is ordered by size fitting
func (instance service) ListTemplatesBySizing(
	inctx context.Context, sizing abstract.HostSizingRequirements, force bool,
) (selectedTpls []*abstract.HostTemplate, rerr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(inctx, true, "").Entering()
	defer tracer.Exiting()

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  []*abstract.HostTemplate
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		allTpls, rerr := instance.ListTemplates(ctx, false)
		if rerr != nil {
			chRes <- result{nil, rerr}
			return
		}

		scannerTpls := map[string]bool{}
		askedForSpecificScannerInfo := sizing.MinGPU >= 0 || sizing.MinCPUFreq != 0
		if askedForSpecificScannerInfo {
			_ = os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777)
			db, err := scribble.New(utils.AbsPathify("$HOME/.safescale/scanner/db"), nil)
			if err != nil {
				if force {
					logrus.WithContext(ctx).Warnf("Problem creating / accessing Scanner database, ignoring GPU and Freq parameters for now...: %v", err)
				} else {
					var noHostError string
					if sizing.MinCPUFreq <= 0 {
						noHostError = fmt.Sprintf("unable to create a host with '%d' GPUs, problem accessing Scanner database: %v", sizing.MinGPU, err)
					} else {
						noHostError = fmt.Sprintf("unable to create a host with '%d' GPUs and '%.01f' MHz clock frequency, problem accessing Scanner database: %v", sizing.MinGPU, sizing.MinCPUFreq, err)
					}
					chRes <- result{nil, fail.NewError(noHostError)}
					return
				}
			} else {
				authOpts, rerr := instance.GetAuthenticationOptions(ctx)
				if rerr != nil {
					chRes <- result{nil, rerr}
					return
				}

				region, ok := authOpts.Get("Region")
				if !ok {
					chRes <- result{nil, fail.SyntaxError("region value unset")}
					return
				}

				svcName, xerr := instance.GetName()
				if xerr != nil {
					chRes <- result{nil, xerr}
					return
				}

				folder := fmt.Sprintf("images/%s/%s", svcName, region)

				imageList, err := db.ReadAll(folder)
				if err != nil {
					if force {
						logrus.WithContext(ctx).Warnf("Problem creating / accessing Scanner database, ignoring GPU and Freq parameters for now...: %v", err)
					} else {
						var noHostError string
						if sizing.MinCPUFreq <= 0 {
							noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs, problem accessing Scanner database: %v", sizing.MinGPU, err)
						} else {
							noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs and '%.01f' MHz clock frequency, problem accessing Scanner database: %v", sizing.MinGPU, sizing.MinCPUFreq, err)
						}
						logrus.WithContext(ctx).Error(noHostError)
						chRes <- result{nil, fail.NewError(noHostError)}
						return
					}
				} else {
					var images []abstract.StoredCPUInfo
					for _, f := range imageList {
						imageFound := abstract.StoredCPUInfo{}
						if err := json.Unmarshal(f, &imageFound); err != nil {
							chRes <- result{nil, fail.Wrap(err, "error unmarshalling image '%s'")}
							return
						}

						// if the user asked explicitly no gpu
						if sizing.MinGPU == 0 && imageFound.GPU != 0 {
							continue
						}

						if imageFound.GPU < sizing.MinGPU {
							continue
						}

						if imageFound.CPUFrequency < float64(sizing.MinCPUFreq) {
							continue
						}

						images = append(images, imageFound)
					}

					if !force && (len(images) == 0) {
						var noHostError string
						if sizing.MinCPUFreq <= 0 {
							noHostError = fmt.Sprintf(
								"Unable to create a host with '%d' GPUs, no images matching requirements", sizing.MinGPU,
							)
						} else {
							noHostError = fmt.Sprintf(
								"Unable to create a host with '%d' GPUs and a CPU clock frequencyof '%.01f MHz', no images matching requirements",
								sizing.MinGPU, sizing.MinCPUFreq,
							)
						}
						logrus.WithContext(ctx).Error(noHostError)
						chRes <- result{nil, fail.NewError(noHostError)}
						return
					}

					for _, image := range images {
						scannerTpls[image.TemplateID] = true
					}
				}
			}
		}

		reducedTmpls := instance.reduceTemplates(allTpls, instance.whitelistTemplateREs, instance.blacklistTemplateREs)
		if sizing.MinGPU < 1 {
			// Force filtering of known templates with GPU from template list when sizing explicitly asks for no GPU
			gpus, xerr := instance.GetRegexpsOfTemplatesWithGPU()
			if xerr != nil {
				chRes <- result{nil, xerr}
				return
			}
			reducedTmpls = instance.reduceTemplates(reducedTmpls, nil, gpus)
		}

		if sizing.MinCores == 0 && sizing.MaxCores == 0 && sizing.MinRAMSize == 0 && sizing.MaxRAMSize == 0 {
			logrus.WithContext(ctx).WithContext(ctx).Debugf("Looking for a host template as small as possible")
		} else {
			coreMsg := ""
			if sizing.MinCores > 0 {
				if sizing.MaxCores > 0 {
					coreMsg = fmt.Sprintf("between %d and %d", sizing.MinCores, sizing.MaxCores)
				} else {
					coreMsg = fmt.Sprintf("at least %d", sizing.MinCores)
				}
			} else {
				coreMsg = fmt.Sprintf("at most %d", sizing.MaxCores)
			}
			ramMsg := ""
			if sizing.MinRAMSize > 0 {
				if sizing.MaxRAMSize > 0 {
					ramMsg = fmt.Sprintf("between %.01f and %.01f", sizing.MinRAMSize, sizing.MaxRAMSize)
				} else {
					ramMsg = fmt.Sprintf("at least %.01f", sizing.MinRAMSize)
				}
			} else {
				coreMsg = fmt.Sprintf("at most %.01f", sizing.MaxRAMSize)
			}
			diskMsg := ""
			if sizing.MinDiskSize > 0 {
				diskMsg = fmt.Sprintf(" and at least %d GB of disk", sizing.MinDiskSize)
			}
			gpuMsg := ""
			if sizing.MinGPU >= 0 {
				gpuMsg = fmt.Sprintf("%d GPU%s", sizing.MinGPU, strprocess.Plural(uint(sizing.MinGPU)))
			}
			logrus.WithContext(ctx).WithContext(ctx).Debugf(
				fmt.Sprintf(
					"Looking for a host template with: %s cores, %s RAM, %s%s", coreMsg, ramMsg, gpuMsg, diskMsg,
				),
			)
		}

		for _, t := range reducedTmpls {
			msg := fmt.Sprintf(
				"Discarded host template '%s' with %d cores, %.01f GB of RAM, %d GPU and %d GB of Disk:", t.Name, t.Cores,
				t.RAMSize, t.GPUNumber, t.DiskSize,
			)
			msg += " %s"
			if sizing.MinCores > 0 && t.Cores < sizing.MinCores {
				logrus.WithContext(ctx).Tracef(msg, "not enough cores")
				continue
			}
			if sizing.MaxCores > 0 && t.Cores > sizing.MaxCores {
				logrus.WithContext(ctx).Tracef(msg, "too many cores")
				continue
			}
			if sizing.MinRAMSize > 0.0 && t.RAMSize < sizing.MinRAMSize {
				logrus.WithContext(ctx).Tracef(msg, "not enough RAM")
				continue
			}
			if sizing.MaxRAMSize > 0.0 && t.RAMSize > sizing.MaxRAMSize {
				logrus.WithContext(ctx).Tracef(msg, "too many RAM")
				continue
			}
			if t.DiskSize > 0 && sizing.MinDiskSize > 0 && t.DiskSize < sizing.MinDiskSize {
				logrus.WithContext(ctx).Tracef(msg, "not enough disk")
				continue
			}
			if t.DiskSize > 0 && sizing.MaxDiskSize > 0 && t.DiskSize > sizing.MaxDiskSize {
				logrus.WithContext(ctx).Tracef(msg, "too many disk")
				continue
			}
			if (sizing.MinGPU <= 0 && t.GPUNumber > 0) || (sizing.MinGPU > 0 && t.GPUNumber > sizing.MinGPU) {
				logrus.WithContext(ctx).Tracef(msg, "too many GPU")
				continue
			}

			if _, ok := scannerTpls[t.ID]; (ok || !askedForSpecificScannerInfo) && t.ID != "" {
				newT := t
				selectedTpls = append(selectedTpls, newT)
			}
		}

		sort.Sort(ByRankDRF(selectedTpls))
		chRes <- result{selectedTpls, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

type scoredImage struct {
	abstract.Image
	score float64
}

type scoredImages []scoredImage

func (a scoredImages) Len() int           { return len(a) }
func (a scoredImages) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a scoredImages) Less(i, j int) bool { return a[i].score < a[j].score }

// FilterImages search an images corresponding to OS Name
func (instance service) FilterImages(inctx context.Context, filter string) ([]*abstract.Image, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  []*abstract.Image
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		imgs, err := instance.ListImages(ctx, false)
		if err != nil {
			chRes <- result{nil, err}
			return
		}
		imgs = instance.reduceImages(imgs)

		if len(filter) == 0 {
			chRes <- result{imgs, nil}
			return
		}
		var simgs []scoredImage
		// fields := strings.Split(strings.ToUpper(osname), " ")
		for _, img := range imgs {
			// score := 1 / float64(smetrics.WagnerFischer(strings.ToUpper(img.Name), strings.ToUpper(osname), 1, 1, 2))
			score := smetrics.JaroWinkler(strings.ToUpper(img.Name), strings.ToUpper(filter), 0.7, 5)
			// score := matchScore(fields, strings.ToUpper(img.Name))
			// score := SimilarityScore(filter, img.Name)
			if score > 0.5 {
				simgs = append(
					simgs, scoredImage{
						Image: *img,
						score: score,
					},
				)
			}

		}
		var fimgs []*abstract.Image
		sort.Sort(scoredImages(simgs))
		for _, simg := range simgs {
			simg := simg
			fimgs = append(fimgs, &simg.Image)
		}

		chRes <- result{fimgs, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

func (instance service) reduceImages(imgs []*abstract.Image) []*abstract.Image {
	var finalFilter *imagefilters.Filter
	if len(instance.whitelistImageREs) > 0 {
		finalFilter = imagefilters.NewFilter(filterImagesByRegexSlice(instance.whitelistImageREs))
	}
	if len(instance.blacklistImageREs) > 0 {
		blackFilter := imagefilters.NewFilter(filterImagesByRegexSlice(instance.blacklistImageREs))
		if finalFilter == nil {
			finalFilter = blackFilter.Not()
		} else {
			finalFilter = finalFilter.And(blackFilter.Not())
		}
	}
	if finalFilter != nil {
		// templateFilter := templatefilters.NewFilter(finalFilter)
		return imagefilters.FilterImages(imgs, finalFilter)
	}
	return imgs
}

func filterImagesByRegexSlice(res []*regexp.Regexp) imagefilters.Predicate {
	return func(img *abstract.Image) bool {
		for _, re := range res {
			if re.Match([]byte(img.Name)) {
				return true
			}
		}
		return false

	}
}

// ListImages reduces the list of needed, if all bool is true, all images are returned, if not, images are filtered using blacklists and whitelists
func (instance service) ListImages(inctx context.Context, all bool) ([]*abstract.Image, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  []*abstract.Image
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		imgs, err := instance.Provider.ListImages(ctx, all)
		if err != nil {
			chRes <- result{nil, err}
			return
		}

		chRes <- result{instance.reduceImages(imgs), nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// SearchImage search an image corresponding to OS Name
func (instance service) SearchImage(inctx context.Context, osname string) (*abstract.Image, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if osname == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("osname")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *abstract.Image
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		imgs, xerr := instance.ListImages(ctx, false)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}
		if len(imgs) == 0 {
			chRes <- result{nil, fail.NotFoundError("unable to find an image matching '%s', 0 results returned by the service listing images", osname)}
			return
		}

		reg := regexp.MustCompile("[^A-Z0-9]")

		var maxLength int
		for _, img := range imgs {
			length := len(img.Name)
			if maxLength < length {
				maxLength = length
			}
		}

		normalizedOSName := normalizeString(osname, reg)
		paddedNormalizedOSName := addPadding(normalizedOSName, maxLength)

		minWFScore := -1
		wfSelect := -1
		for i, entry := range imgs {
			normalizedImageName := normalizeString(entry.Name, reg)
			normalizedImageName = addPadding(normalizedImageName, maxLength)
			if strings.Contains(normalizedImageName, normalizedOSName) {
				wfScore := smetrics.WagnerFischer(paddedNormalizedOSName, normalizedImageName, 1, 1, 2)
				logrus.WithContext(ctx).Tracef("%*s (%s): WagnerFischerScore:%4d", maxLength, entry.Name, normalizedImageName, wfScore)

				if minWFScore == -1 || wfScore < minWFScore {
					minWFScore = wfScore
					wfSelect = i
				}
			}
		}

		if wfSelect < 0 {
			chRes <- result{nil, fail.NotFoundError("unable to find an image matching '%s'", osname)}
			return
		}

		logrus.WithContext(ctx).Infof("Selected image: '%s' (ID='%s')", imgs[wfSelect].Name, imgs[wfSelect].ID)
		chRes <- result{imgs[wfSelect], nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

func normalizeString(in string, reg *regexp.Regexp) string {
	in = strings.ToUpper(in)
	in = reg.ReplaceAllString(in, "")
	return in
}

func addPadding(in string, maxLength int) string {
	if maxLength <= 0 {
		return in
	}

	length := len(in)
	if length < maxLength {
		paddingRight := maxLength - length
		in += strings.Repeat(" ", paddingRight)
	}
	return in
}

// CreateHostWithKeyPair creates a host
func (instance service) CreateHostWithKeyPair(inctx context.Context, request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, *abstract.KeyPair, fail.Error) {
	if valid.IsNil(instance) {
		return nil, nil, nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		hf   *abstract.HostFull
		uc   *userdata.Content
		ak   *abstract.KeyPair
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		found := true
		ah := abstract.NewHostCore()
		ah.Name = request.ResourceName
		_, rerr := instance.InspectHost(ctx, ah)
		var nilErrNotFound *fail.ErrNotFound = nil // nolint
		if rerr != nil && rerr != nilErrNotFound {
			if _, ok := rerr.(*fail.ErrNotFound); !ok { // nolint, typed nil already taken care in previous line
				chRes <- result{nil, nil, nil, fail.ConvertError(rerr)}
				return
			}
			found = false
			debug.IgnoreError(rerr)
		}

		if found {
			chRes <- result{nil, nil, nil, abstract.ResourceDuplicateError("host", request.ResourceName)}
			return
		}

		// Create temporary key pair
		kpNameuuid, err := uuid.NewV4()
		if err != nil {
			chRes <- result{nil, nil, nil, fail.ConvertError(err)}
			return
		}

		kpName := kpNameuuid.String()
		kp, rerr := instance.CreateKeyPair(ctx, kpName)
		if rerr != nil {
			chRes <- result{nil, nil, nil, rerr}
			return
		}

		// Create host
		hostReq := abstract.HostRequest{
			ResourceName:   request.ResourceName,
			HostName:       request.HostName,
			ImageID:        request.ImageID,
			ImageRef:       request.ImageID,
			KeyPair:        kp,
			PublicIP:       request.PublicIP,
			Subnets:        request.Subnets,
			DefaultRouteIP: request.DefaultRouteIP,
			DiskSize:       request.DiskSize,
			// DefaultGateway: request.DefaultGateway,
			TemplateID: request.TemplateID,
		}
		host, userData, rerr := instance.CreateHost(ctx, hostReq, nil)
		if rerr != nil {
			chRes <- result{nil, nil, nil, rerr}
			return
		}
		chRes <- result{host, userData, kp, nil}

	}()
	select {
	case res := <-chRes:
		return res.hf, res.uc, res.ak, res.rErr
	case <-ctx.Done():
		return nil, nil, nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, nil, nil, fail.ConvertError(inctx.Err())
	}

}

// ListHostsWithTags list hosts with tags
func (instance service) ListHostsWithTags(inctx context.Context, labels []string, details map[string]string) ([]*abstract.HostFull, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  []*abstract.HostFull
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		var varhosts []*abstract.HostFull

		hosts, err := instance.ListHosts(ctx, true)
		if err != nil {
			chRes <- result{nil, err}
			return
		}

		if len(labels) > 0 {
			for _, host := range hosts {
				there := true
				for _, k := range labels {
					_, ok := host.Core.Tags[k]
					if !ok {
						there = false
						break
					}
				}
				if there {
					varhosts = append(varhosts, host)
				}
			}
		}

		for _, host := range hosts {
			there := true
			for k, v := range details {
				av, ok := host.Core.Tags[k]
				if ok {
					if av != v {
						there = false
						break
					}
				} else {
					there = false
					break
				}
			}
			if there {
				varhosts = append(varhosts, host)
			}
		}

		chRes <- result{varhosts, nil}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

}

// TenantCleanup removes everything related to SafeScale from tenant (mainly metadata)
// if force equals false and there is metadata, returns an error
// WARNING: !!! this will make SafeScale unable to handle the resources !!!
func (instance service) TenantCleanup(ctx context.Context, force bool) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	return fail.NotImplementedError("service.TenantCleanup() not yet implemented") // FIXME: Technical debt
}

// LookupRuleInSecurityGroup checks if a rule is already in Security Group rules
func (instance service) LookupRuleInSecurityGroup(
	inctx context.Context, asg *abstract.SecurityGroup, rule *abstract.SecurityGroupRule,
) (bool, fail.Error) {
	if valid.IsNil(asg) {
		return false, fail.InvalidParameterError("asg", "cannot be null value of '*abstract.SecurityGroup'")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  bool
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		_, xerr := asg.Rules.IndexOfEquivalentRule(rule)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				chRes <- result{false, nil}
				return
			default:
				chRes <- result{false, xerr}
				return
			}
		}
		chRes <- result{true, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return false, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return false, fail.ConvertError(inctx.Err())
	}
}

// InspectHostByName hides the "complexity" of the way to get Host by name
func (instance service) InspectHostByName(inctx context.Context, name string) (*abstract.HostFull, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *abstract.HostFull
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		ah, xerr := instance.InspectHost(ctx, abstract.NewHostCore().SetName(name))
		chRes <- result{ah, xerr}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

func (instance service) GetCache(inctx context.Context) (cache.CacheInterface, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// Enable cache by default, too many consistency errors otherwise
	if beta := os.Getenv("SAFESCALE_CACHE"); beta != "disabled" {
		return instance.cacheManager, nil
	}

	return nil, nil
}

// InspectSecurityGroupByName hides the "complexity" of the way to get Security Group by name
func (instance service) InspectSecurityGroupByName(inctx context.Context, networkID string, name string) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *abstract.SecurityGroup
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		as, xerr := instance.InspectSecurityGroup(ctx, abstract.NewSecurityGroup().SetName(name).SetNetworkID(networkID))
		chRes <- result{as, xerr}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// ObjectStorageConfiguration returns the configuration of Object Storage location
func (instance service) ObjectStorageConfiguration(inctx context.Context) (objectstorage.Config, fail.Error) {
	if valid.IsNil(instance) {
		return objectstorage.Config{}, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  objectstorage.Config
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		oc, xerr := instance.Location.Configuration()
		chRes <- result{oc, xerr}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return objectstorage.Config{}, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return objectstorage.Config{}, fail.ConvertError(inctx.Err())
	}
}
