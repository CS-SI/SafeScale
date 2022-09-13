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

package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	uuidpkg "github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/metadata"
)

// Job is the interface of a daemon job
type Job interface {
	ID() string
	Name() string
	Context() context.Context
	Task() concurrency.Task
	Tenant() string
	Service() iaas.Service
	Duration() time.Duration
	String() string

	Abort() fail.Error
	Aborted() (bool, fail.Error)
	Close()
}

// job contains the information needed by safescaled to execute a request
type job struct {
	description string
	uuid        string
	tenant      string
	ctx         context.Context
	task        concurrency.Task
	cancel      context.CancelFunc
	service     iaas.Service
	startTime   time.Time
}

var (
	jobMap          = map[string]Job{}
	mutexJobManager sync.Mutex
)

// NewJob creates a new instance of struct Job
func NewJob(ctx context.Context, cancel context.CancelFunc, svc iaas.Service, description string) (_ *job, ferr fail.Error) { // nolint
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if cancel == nil {
		return nil, fail.InvalidParameterCannotBeNilError("cancel")
	}

	var (
		md metadata.MD
		id string
		ok bool
	)

	md, ok = metadata.FromIncomingContext(ctx)
	if !ok {
		logrus.Warn("context does not contain a grpc uuid, generating one")
		uuid, err := uuidpkg.NewV4()
		if err != nil {
			return nil, fail.Wrap(err, "failed to generate uuid for job")
		}

		id = uuid.String()
	} else {
		u := md.Get("uuid")
		if len(u) == 0 {
			logrus.Warnf(fail.InvalidParameterError("ctx", "does not contain a grpc uuid").Error())
		} else {
			if id = u[0]; id == "" {
				logrus.Warnf(fail.InvalidParameterError("ctx", "does not contain a valid gRPC uuid").Error())
			}
		}

		uuid, err := uuidpkg.NewV4()
		if err != nil {
			return nil, fail.Wrap(err, "failed to generate uuid for job")
		}

		id = uuid.String()
	}

	task, xerr := concurrency.NewTaskWithContext(ctx)
	if xerr != nil {
		return nil, xerr
	}

	if xerr = task.SetID(id + description); xerr != nil {
		return nil, xerr
	}

	// attach task instance to the context
	ctx = context.WithValue(ctx, concurrency.KeyForTaskInContext, task) // nolint
	ctx = context.WithValue(ctx, concurrency.KeyForID, id)              // nolint

	nj := job{
		description: description,
		uuid:        id,
		ctx:         ctx,
		task:        task,
		cancel:      cancel,
		service:     svc,
		startTime:   time.Now(),
	}
	if svc != nil {
		nj.tenant, xerr = svc.GetName()
		if xerr != nil {
			return nil, xerr
		}
	}
	if xerr = register(&nj); xerr != nil {
		return nil, xerr
	}

	return &nj, nil
}

// IsNull tells if the instance represents a null value
func (instance *job) IsNull() bool {
	return instance == nil || instance.uuid == ""
}

// ID returns the id of the job (ie the uuid of gRPC message)
func (instance job) ID() string {
	return instance.uuid
}

// Name returns the name (== id) of the job
func (instance job) Name() string {
	return instance.uuid
}

// Tenant returns the tenant to use
func (instance job) Tenant() string {
	return instance.tenant
}

// Context returns the context of the job (should be the same as the one of the task)
func (instance job) Context() context.Context {
	return instance.ctx
}

// Task returns the task instance
func (instance job) Task() concurrency.Task {
	return instance.task
}

// Service returns the service instance
func (instance job) Service() iaas.Service {
	return instance.service
}

// Duration returns the duration of the job
func (instance job) Duration() time.Duration {
	return time.Since(instance.startTime)
}

// Abort tells the job it has to abort operations
func (instance *job) Abort() (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if instance.cancel == nil {
		return fail.InvalidInstanceContentError("instance.cancel", "cannot be nil")
	}

	instance.cancel()
	instance.cancel = nil
	return nil
}

// Aborted tells if the job has been aborted
func (instance job) Aborted() (bool, fail.Error) {
	status, err := instance.task.Status()
	if err != nil {
		return false, fail.Wrap(err, "problem getting aborted status")
	}
	return status == concurrency.ABORTED, nil
}

// Close tells the job to wait for end of operation; this ensures everything is cleaned up correctly
func (instance *job) Close() {
	_ = deregister(instance)
	if instance.cancel != nil {
		instance.cancel()
	}
}

// String returns a string representation of job information
func (instance job) String() string {
	return fmt.Sprintf("Job: %s (started at %s)", instance.description, instance.startTime.String())
}

// register ...
func register(job Job) fail.Error {
	mutexJobManager.Lock()
	defer mutexJobManager.Unlock()

	jobMap[job.ID()] = job
	return nil
}

// deregister ...
func deregister(job Job) fail.Error {
	if job == nil {
		return fail.InvalidParameterCannotBeNilError("job")
	}

	uuid := job.ID()
	if uuid != "" {
		mutexJobManager.Lock()
		defer mutexJobManager.Unlock()

		if _, ok := jobMap[uuid]; !ok {
			return fail.NotFoundError("failed to find a job identified by id '%s'", uuid)
		}
		delete(jobMap, uuid)
		return nil
	}

	return fail.InvalidParameterError("job", "job id cannot be empty string")
}

// AbortJobByID asks the job identified by 'id' to abort
func AbortJobByID(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	if job, ok := jobMap[id]; ok {
		if xerr := job.Abort(); xerr != nil {
			return fail.Wrap(xerr, "failed to stop job '%s'", id)
		}
		return nil
	}
	return fail.NotFoundError("no job identified by '%s' found", id)
}

// ListJobs ...
func ListJobs() map[string]string {
	listMap := map[string]string{}
	for uuid, job := range jobMap {
		listMap[uuid] = job.Name()
	}
	return listMap
}
