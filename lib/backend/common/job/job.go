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

package job

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api/terraformer"
	uuidpkg "github.com/gofrs/uuid"

	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/versions"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/factory"
	iaasoptions "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// Job is the interface of a daemon job
type Job interface {
	ID() string
	Name() string
	Organization() string
	Project() string
	Tenant() string
	Context() context.Context
	Task() concurrency.Task
	Service() iaasapi.Service
	Duration() time.Duration
	String() string

	Abort() fail.Error
	Aborted() (bool, fail.Error)
	Close()
}

// job contains the information needed by safescaled to execute a request
type job struct {
	scope     Scope
	uuid      string
	ctx       context.Context
	task      concurrency.Task
	cancel    context.CancelFunc
	service   iaasapi.Service
	startTime time.Time
}

var (
	jobMap          = map[string]Job{}
	mutexJobManager sync.Mutex
)

// New creates a new instance of struct Job
func New(ctx context.Context, cancel context.CancelFunc, scope Scope) (_ *job, ferr fail.Error) { // nolint
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if cancel == nil {
		return nil, fail.InvalidParameterCannotBeNilError("cancel")
	}
	if scope.Tenant == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("scope.Tenant")
	}
	if scope.Organization == "" {
		scope.Organization = global.DefaultOrganization
	}
	if scope.Project == "" {
		scope.Project = global.DefaultProject
	}

	// VPL: I don't get the point of checking if context has an uuid or not, as this uuid is not used...
	//      and the logs are then polluted by a useless warning...
	// var (
	//  md metadata.MD
	//  ok bool
	// )
	//
	// md, ok = metadata.FromIncomingContext(ctx)
	// if !ok {
	// 	logrus.Warn("context does not contain a grpc uuid, generating one")
	// 	uuid, err := uuidpkg.NewV4()
	// 	if err != nil {
	// 		return nil, fail.Wrap(err, "failed to generate uuid for job")
	// 	}
	//
	// 	id = uuid.String()
	// } else {
	// 	u := md.Get("uuid")
	// 	if len(u) == 0 {
	// 		logrus.Warnf(fail.InvalidParameterError("ctx", "does not contain a grpc uuid").Error())
	// 	} else {
	// 		if id = u[0]; id == "" {
	// 			logrus.Warnf(fail.InvalidParameterError("ctx", "does not contain a valid gRPC uuid").Error())
	// 		}
	// 	}

	uuid, err := uuidpkg.NewV4()
	if err != nil {
		return nil, fail.Wrap(err, "failed to generate uuid for job")
	}

	id := uuid.String()
	// }

	task, xerr := concurrency.NewTaskWithContext(ctx)
	if xerr != nil {
		return nil, xerr
	}

	xerr = task.SetID(id + scope.Description)
	if xerr != nil {
		return nil, xerr
	}

	nj := &job{
		scope:     scope,
		uuid:      id,
		task:      task,
		cancel:    cancel,
		startTime: time.Now(),
	}

	// attach task instance to the context
	// ctx = context.WithValue(ctx, concurrency.KeyForTaskInContext, task) // nolint
	// ctx = context.WithValue(ctx, concurrency.KeyForID, id)              // nolint
	// attach job instance to the context
	ctx = context.WithValue(ctx, KeyForJobInContext, nj) // nolint
	nj.ctx = ctx

	providerProfile, xerr := factory.FindProviderProfileForTenant(scope.Tenant)
	if xerr != nil {
		return nil, xerr
	}

	svcOptions := []options.Mutator{
		iaasoptions.BuildWithTenant(scope.Tenant),
	}
	if providerProfile.Capabilities().UseTerraformer {
		config, xerr := prepareTerraformerConfiguration(providerProfile, scope)
		if xerr != nil {
			return nil, xerr
		}

		svcOptions = append(svcOptions, iaasoptions.BuildWithTerraformer(config))
	}

	service, xerr := factory.UseService(svcOptions...)
	if xerr != nil {
		return nil, xerr
	}

	// bucket, ierr := service.GetMetadataBucket(ctx)
	// if ierr != nil {
	// 	return nil, ierr
	// }
	//
	// tenant = &operations.Tenant{Name: providerProfile.Name(), BucketName: bucket.GetName(), Service: service}

	nj.service = service
	xerr = register(nj)
	if xerr != nil {
		return nil, xerr
	}

	return nj, nil
}

func prepareTerraformerConfiguration(providerProfile *providers.Profile, scope Scope) (terraformerapi.Configuration, fail.Error) {
	if valid.IsNull(providerProfile) {
		return terraformerapi.Configuration{}, fail.InvalidParameterCannotBeNilError("providerProfile")
	}

	workDir := filepath.Join(global.Settings.Folders.TmpDir, "terraform", scope.Organization, scope.Project, scope.Tenant)
	out := terraformerapi.Configuration{
		Release:           "= " + versions.Terraformv1_2_6.String(),
		WorkDir:           workDir,
		ExecPath:          global.Settings.Backend.Terraform.ExecPath,
		RequiredProviders: providerProfile.TerraformProviders(),
	}

	return out, nil
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

// Organization returns the organization of the job
func (instance job) Organization() string {
	return instance.scope.Organization
}

// Project returns the project of the job
func (instance job) Project() string {
	return instance.scope.Project
}

// Tenant returns the tenant of the job
func (instance job) Tenant() string {
	return instance.scope.Tenant
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
func (instance job) Service() iaasapi.Service {
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
	return fmt.Sprintf("Job: %s (started at %s)", instance.scope.Description, instance.startTime.String())
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
