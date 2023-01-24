/*
 * Copyright 2018-2023, CS Systemes d'Information, http://ctagroup.eu
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

package label

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// New creates an instance of *Label
func New(ctx context.Context) (_ *resources.Label, ferr fail.Error) {
	return resources.NewLabel(ctx)
}

// Load loads the metadata of Security Group a,d returns an instance of *Label
func Load(ctx context.Context, ref string) (_ *resources.Label, ferr fail.Error) {
	return resources.LoadLabel(ctx, ref)
}
