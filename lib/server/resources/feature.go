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

package resources

import (
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

// Targetable is an interface that target must satisfy to be able to install something on it
type Targetable interface {
	data.Identifyable

	// GetTargetType returns the type of the target
	GetTargetType() featuretargettype.Enum
	// GetInstallMethods returns a list of installation methods useable on the target, ordered from upper to lower preference (1 = highest preference)
	GetInstallMethods(concurrency.Task) map[uint8]installmethod.Enum
	// GetInstalledFatures returns a list of installed features
	GetInstalledFeatures(concurrency.Task) []string
	// ComplementFeatureParameters adds parameters corresponding to the target in preparation of feature installation
	ComplementFeatureParameters(t concurrency.Task, v data.Map) error
}

// Feature defines the interface of feature
type Feature interface {
	data.Clonable

	// GetName returns the name of the feature
	GetName() string
	// GetFilename returns the filename of the feature
	GetFilename() string
	// GetDisplayFilename displays the filename of display (optionally adding '[embedded]' for embedded features)
	GetDisplayFilename() string
	// GetSpecs returns the feature specs
	GetSpecs() *viper.Viper
	// Requirements returns the other features needed as requirements
	GetRequirements() ([]string, error)
	// Applyable tells if the feature is installable on the target
	Applyable(Targetable) bool
	// Check if feature is installed on target
	Check(t Targetable, v data.Map, fs FeatureSettings) (Results, error)
	// Add installs the feature on the target
	Add(t Targetable, v data.Map, fs FeatureSettings) (Results, error)
	// Remove uninstalls the feature from the target
	Remove(t Targetable, v data.Map, fs FeatureSettings) (Results, error)
}

// FeatureSettings are used to tune the feature
type FeatureSettings struct {
	// SkipProxy to tell not to try to set reverse proxy
	SkipProxy bool
	// Serialize force not to parallel hosts in step
	Serialize bool
	// SkipFeatureRequirements tells not to install required features
	SkipFeatureRequirements bool
	// SkipSizingRequirements tells not to check sizing requirements
	SkipSizingRequirements bool
	// AddUnconditionally tells to not check before addition (no effect for check or removal)
	AddUnconditionally bool
}
