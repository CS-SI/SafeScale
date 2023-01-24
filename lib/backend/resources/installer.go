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

package resources

import (
	"context"

	rscapi "github.com/CS-SI/SafeScale/v22/lib/backend/resources/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
)

//go:generate minimock -o ../mocks/mock_installer.go -i github.com/CS-SI/SafeScale/v22/lib/backend/resources.Installer

// Installer defines the API of an Installer
type Installer interface {
	Check(context.Context, *Feature, Targetable, data.Map[string, any], ...options.Option) (rscapi.Results, fail.Error)  // checks if a Feature is installed
	Add(context.Context, *Feature, Targetable, data.Map[string, any], ...options.Option) (rscapi.Results, fail.Error)    // executes installation of Feature
	Remove(context.Context, *Feature, Targetable, data.Map[string, any], ...options.Option) (rscapi.Results, fail.Error) // executes deletion of Feature
}
