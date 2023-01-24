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

	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
)

// cleanerCtx copies the task id value into a new context derived from context.Background
// the idea is to use cleanerCtx for cleanup (or undo) operations -> if the main task is cancelled, it stops, but its cleanup (that initially shared the same task id, and because of that it might be cancelled too, won't)
func cleanerCtx(ctx context.Context) (context.Context, error) { // nolint
	derived := context.WithValue(context.Background(), concurrency.KeyForTaskInContext, ctx.Value(concurrency.KeyForTaskInContext)) // nolint
	return derived, nil
}
