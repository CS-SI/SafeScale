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
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// unsafeGetSpeed ...
// Intended to be used when instance is notoriously not nil
func (instance *volume) unsafeGetSpeed(ctx context.Context) (volumespeed.Enum, fail.Error) {
	var speed volumespeed.Enum
	xerr := instance.Review(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		av, innerErr := clonable.Cast[*abstract.Volume](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		speed = av.Speed
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return speed, nil
}

// unsafeGetSize ...
// Intended to be used when instance is notoriously not nil
func (instance *volume) unsafeGetSize(ctx context.Context) (int, fail.Error) {
	var size int
	xerr := instance.Review(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		av, innerErr := clonable.Cast[*abstract.Volume](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		size = av.Size
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return size, nil
}
