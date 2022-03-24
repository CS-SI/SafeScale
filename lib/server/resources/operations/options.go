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

package operations

import (
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
)

const (
	optionWithoutReloadKeyword = "without_reload"
)

var (
	// WithoutReloadOption is used as option to LoadXXX() to disable reloading from metadata and/or local instance caching (that may lead to deadlock sometimes)
	WithoutReloadOption = data.NewImmutableKeyValue(optionWithoutReloadKeyword, true)
	// WithReloadOption is used as option to LoadXXX() to enable reloading from metadata
	WithReloadOption = data.NewImmutableKeyValue(optionWithoutReloadKeyword, false)
)
