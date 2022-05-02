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

package resources

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/server/resources.Feature -o mocks/mock_feature.go

// Targetable is an interface that target must satisfy to be able to install something on it
type Targetable interface {
	data.Identifiable

	ComplementFeatureParameters(ctx context.Context, v data.Map) fail.Error                                // adds parameters corresponding to the Target in preparation of feature installation
	UnregisterFeature(ctx context.Context, feat string) fail.Error                                         // unregisters a Feature from Target in metadata
	InstalledFeatures(ctx context.Context) []string                                                        // returns a list of installed features
	InstallMethods(ctx context.Context) (map[uint8]installmethod.Enum, fail.Error)                         // returns a list of installation methods usable on the target, ordered from upper to lower preference (1 = the highest preference)
	RegisterFeature(ctx context.Context, feat Feature, requiredBy Feature, clusterContext bool) fail.Error // registers a feature on target in metadata
	Service() iaas.Service                                                                                 // returns the iaas.Service used by the target
	TargetType() featuretargettype.Enum                                                                    // returns the type of the target
}

// Feature defines the interface of feature
type Feature interface {
	data.Clonable
	data.Identifiable

	Add(ctx context.Context, t Targetable, v data.Map, fs FeatureSettings) (Results, fail.Error)    // installs the feature on the target
	Applicable(ctx context.Context, tg Targetable) (bool, fail.Error)                               // tells if the feature is installable on the target
	Check(ctx context.Context, t Targetable, v data.Map, fs FeatureSettings) (Results, fail.Error)  // check if feature is installed on target
	GetDisplayFilename(ctx context.Context) string                                                  // displays the filename of display (optionally adding '[embedded]' for embedded features)
	GetFilename(ctx context.Context) string                                                         // returns the filename of the feature
	Dependencies(ctx context.Context) (map[string]struct{}, fail.Error)                             // returns the other features needed as requirements
	ListParametersWithControl(ctx context.Context) []string                                         // returns a list of parameter containing version information
	Remove(ctx context.Context, t Targetable, v data.Map, fs FeatureSettings) (Results, fail.Error) // uninstalls the feature from the target
	ToProtocol(ctx context.Context) *protocol.FeatureResponse
}

// FeatureSettings are used to tune the feature
type FeatureSettings struct {
	SkipProxy               bool // to tell not to try to set reverse proxy
	Serialize               bool // force not to parallel hosts in step
	SkipFeatureRequirements bool // tells not to install required features
	SkipSizingRequirements  bool // tells not to check sizing requirements
	AddUnconditionally      bool // tells to not check before addition (no effect for check or removal)
	IgnoreSuitability       bool // allows to not check if the feature is suitable for the target
}
