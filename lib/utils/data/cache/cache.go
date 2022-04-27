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

package cache

//go:generate minimock -o mocks/mock_cache.go -i github.com/CS-SI/SafeScale/v22/lib/utils/data/cache.Cache

import (
	"context"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Cache interface describing what a struct must implement to be considered as a cache
type Cache interface {
	Get(ctx context.Context, key string, options ...data.ImmutableKeyValue) (ce *Entry, xerr fail.Error)
	ReserveEntry(ctx context.Context, key string, timeout time.Duration) fail.Error
	CommitEntry(ctx context.Context, key string, content Cacheable) (ce *Entry, xerr fail.Error)
	FreeEntry(ctx context.Context, key string) fail.Error
	AddEntry(ctx context.Context, content Cacheable) (ce *Entry, xerr fail.Error)
}
