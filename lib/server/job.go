/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	uuidpkg "github.com/satori/go.uuid"
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
	Aborted() bool
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
func NewJob(ctx context.Context, cancel context.CancelFunc, svc iaas.Service, description string) (_ *job, xerr fail.Error) { //nolint
	defer fail.OnPanic(&xerr)

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
			return nil, fail.InvalidParameterError("ctx", "does not contain a grpc uuid")
		}

		if id = u[0]; id == "" {
			return nil, fail.InvalidParameterError("ctx", "does not contain a valid gRPC uuid")
		}
	}

	task, xerr := concurrency.NewTaskWithContext(ctx)
	if xerr != nil {
		return nil, xerr
	}

	if xerr = task.SetID(id+description); xerr != nil {
		return nil, xerr
	}

	// attach task instance to the context
	ctx = context.WithValue(ctx, concurrency.KeyForTaskInContext, task)

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
		nj.tenant = svc.GetName()
	}
	if xerr = register(&nj); xerr != nil {
		return nil, xerr
	}

	return &nj, nil
}

// isNull tells if the instance represents a null value
func (j *job) isNull() bool {
	return j == nil || j.uuid == ""
}

// ID returns the id of the job (ie the uuid of gRPC message)
func (j job) ID() string {
	if j.isNull() {
		return ""
	}

	return j.uuid
}

// Name returns the name (== id) of the job
func (j job) Name() string {
	if j.isNull() {
		return ""
	}

	return j.uuid
}

// Tenant returns the tenant to use
func (j job) Tenant() string {
	if j.isNull() {
		return ""
	}

	return j.tenant
}

// Context returns the context of the job (should be the same than the one of the task)
func (j job) Context() context.Context {
	if j.isNull() {
		return nil
	}

	return j.ctx
}

// Task returns the task instance
func (j job) Task() concurrency.Task {
	if j.isNull() {
		return nil
	}

	return j.task
}

// Service returns the service instance
func (j job) Service() iaas.Service {
	if j.isNull() {
		return iaas.NullService()
	}

	return j.service
}

// Duration returns the duration of the job
func (j job) Duration() time.Duration {
	if j.isNull() {
		return 0
	}

	return time.Since(j.startTime)
}

// Abort tells the job it has to abort operations
func (j *job) Abort() (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if j.isNull() {
		return fail.InvalidInstanceError()
	}
	if j.cancel == nil {
		return fail.InvalidInstanceContentError("j.cancel", "cannot be nil")
	}

	j.cancel()
	j.cancel = nil
	return nil
}

// Aborted tells if the job has been aborted
func (j job) Aborted() bool {
	if j.isNull() {
		return false
	}

	status, _ := j.task.Status()
	return status == concurrency.ABORTED
}

// Close tells the job to wait for end of operation; this ensure everything is cleaned up correctly
func (j *job) Close() {
	if j.isNull() {
		return
	}

	_ = deregister(j)
	if j.cancel != nil {
		j.cancel()
	}
}

// String returns a string representation of job information
func (j job) String() string {
	if j.isNull() {
		return ""
	}
	return fmt.Sprintf("Job: %s (started at %s)", j.description, j.startTime.String())
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
func AbortJobByID(id string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

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
