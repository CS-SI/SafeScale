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

package options

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type Option func(o Options) fail.Error

type Options interface {
	Load(key string) (any, fail.Error)
	Store(key string, value any) fail.Error
	StoreMany(entries ...Entry) fail.Error
	Subset(keys ...string) (Options, fail.Error)
}
