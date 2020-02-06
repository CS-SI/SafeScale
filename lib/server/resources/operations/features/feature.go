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

package features

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/spf13/viper"
)

// Feature defines the interface of feature
type Feature interface {
	// Name returns the name of the feature
	Name() string
	// GetFilename returns the filename of the feature
	Filename() string
	// GetDisplayFilename displays the filename of display (optionally adding '[embedded]' for embedded features)
	DisplayFilename() string
	// GetSpecs returns the feature specs
	Specs() *viper.Viper
	// Clone copies a Feature allowing change of task and svc and reinitializing installers
	Clone(concurrency.Task, iaas.Service) (Feature, error)
	// Applyable tells if the feature is installable on the target
	Applyable(Targetable) bool
	// Check if feature is installed on target
	Check(t Targetable, v data.Map, s Settings) (Results, error)
	// Add installs the feature on the target
	Add(t Targetable, v data.Map, s Settings) (Results, error)
	// Remove uninstalls the feature from the target
	Remove(target Targetable, v data.Map, s Settings) (Results, error)
}
