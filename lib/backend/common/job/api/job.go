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

package jobapi

import (
	"context"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/common/scope/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// Job is the interface of a daemon job
type Job interface {
	ID() string
	IsNull() bool
	Name() string
	Scope() scopeapi.Scope
	Context() context.Context
	Task() concurrency.Task
	Service() iaasapi.Service
	Duration() time.Duration
	String() string

	Abort() fail.Error
	Aborted() (bool, fail.Error)
	Close()
}

const (
	KeyForJobInContext = "job"
)

// FromContext returns the job instance carried by the context
func FromContext(ctx context.Context) (Job, fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	value := ctx.Value(KeyForJobInContext)
	if value == nil {
		return nil, fail.InconsistentError("missing valid Job in context")
	}

	jobInstance, ok := value.(Job)
	if !ok {
		return nil, fail.InconsistentError("value in context must satisfy interface 'Job'")
	}

	if valid.IsNull(jobInstance) {
		return nil, fail.InconsistentError("missing valid Job in context")
	}

	return jobInstance, nil
}

// NewContextPropagatingJob creates a new context from context.Background() and adds job value inside source context
func NewContextPropagatingJob(srcctx context.Context) context.Context {
	newctx := context.Background()

	myjob, xerr := FromContext(srcctx)
	if xerr == nil {
		newctx = context.WithValue(newctx, KeyForJobInContext, myjob)
	}

	return newctx
}
