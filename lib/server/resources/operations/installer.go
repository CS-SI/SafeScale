/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package operations

import (
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate mockgen -destination=../mocks/mock_installer.go -package=mocks github.com/CS-SI/SafeScale/lib/server/resources/operations Installer

// Installer defines the API of an Installer
type Installer interface {
	// Check checks if the feature is installed
	Check(resources.Feature, resources.Targetable, data.Map, resources.FeatureSettings) (resources.Results, fail.Error)
	// Add executes installation of feature
	Add(resources.Feature, resources.Targetable, data.Map, resources.FeatureSettings) (resources.Results, fail.Error)
	// Remove executes deletion of feature
	Remove(resources.Feature, resources.Targetable, data.Map, resources.FeatureSettings) (resources.Results, fail.Error)
}
