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
	"testing"

	"github.com/stretchr/testify/require"
)

// func Test_cleanerCtx(t *testing.T) {
//
// 	ctx := context.Background()
// 	task, xerr := concurrency.NewTaskWithContext(ctx)
// 	ctx = context.WithValue(ctx, "task", task)
// 	require.Nil(t, xerr)
//
// 	derived, err := cleanerCtx(ctx)
// 	require.Nil(t, err)
// 	require.NotNil(t, derived.Value("task"))
//
// }

func Test_cleanupContextFrom(t *testing.T) {
	ctx := context.WithValue(context.Background(), "ID", "toto")

	derived := cleanupContextFrom(ctx)
	require.NotNil(t, derived.Value("ID"))
}
