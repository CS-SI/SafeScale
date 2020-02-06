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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

//go:generate mockgen -destination=../mocks/mock_target.go -package=mocks github.com/CS-SI/SafeScale/lib/server/feature Target

// Targetable is an interface that target must satisfy to be able to install something on it
type Targetable interface {
	data.Identifyable

	// // Name returns the name of the target
	// Name(concurrency.Task) string
	// Type returns the type of the target
	Type() string
	// InstallMethods returns a list of installation methods useable on the target, ordered from upper to lower preference (1 = highest preference)
	InstallMethods(concurrency.Task) map[uint8]installmethod.Enum
	// GetInstalledFatures returns a list of installed features
	InstalledFeatures(concurrency.Task) []string
	// ComplementFeatureParameters adds parameters corresponding to the target in preparation of feature installation
	ComplementFeatureParameters(t concurrency.Task, v data.Map) error
}
