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

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Targetable is an interface that target must satisfy to be able to install something on it
type Targetable interface {
	data.Identifiable

	ComplementFeatureParameters(ctx context.Context, v data.Map) fail.Error        // adds parameters corresponding to the Target in preparation of feature installation
	UnregisterFeature(f string) fail.Error                                         // unregisters a Feature from Target in metadata
	InstalledFeatures() []string                                                   // returns a list of installed features
	InstallMethods() map[uint8]installmethod.Enum                                  // returns a list of installation methods usable on the target, ordered from upper to lower preference (1 = highest preference)
	RegisterFeature(f Feature, requiredBy Feature, clusterContext bool) fail.Error // registers a feature on target in metadata
	TargetType() featuretargettype.Enum                                            // returns the type of the target
}

// Feature defines the interface of feature
type Feature interface {
	data.Clonable
	data.Identifiable

	Add(ctx context.Context, t Targetable, v data.Map, fs FeatureSettings) (Results, fail.Error)    // Add installs the feature on the target
	Applyable(Targetable) bool                                                                      // Applyable tells if the feature is installable on the target
	GetDisplayFilename() string                                                                     // GetDisplayFilename displays the filename of display (optionally adding '[embedded]' for embedded features)
	GetFilename() string                                                                            // GetFilename returns the filename of the feature
	GetRequirements() (map[string]struct{}, fail.Error)                                             // GetRequirements returns the other features needed as requirements
	Check(ctx context.Context, t Targetable, v data.Map, fs FeatureSettings) (Results, fail.Error)  // Check if feature is installed on target
	Remove(ctx context.Context, t Targetable, v data.Map, fs FeatureSettings) (Results, fail.Error) // Remove uninstalls the feature from the target
	ToProtocol() *protocol.FeatureResponse
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
