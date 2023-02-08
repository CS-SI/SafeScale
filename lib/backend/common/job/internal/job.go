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

package internal

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"time"

	scopeapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/scope/api"
	uuidpkg "github.com/gofrs/uuid"
	"github.com/puzpuzpuz/xsync"

	"github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/consul/consumer"
	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/versions"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	tenantfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/tenant"
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// job contains the information needed by safescaled to execute a request
type job struct {
	scope     scopeapi.Scope
	uuid      string
	ctx       context.Context
	task      concurrency.Task
	cancel    context.CancelFunc
	service   iaasapi.Service
	kv        *consumer.KV
	startTime time.Time
}

var JobList *xsync.MapOf[string, jobapi.Job]

// New creates a new instance of struct Job
func New(ctx context.Context, cancel context.CancelFunc, scope scopeapi.Scope) (_ *job, ferr fail.Error) { // nolint
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if cancel == nil {
		return nil, fail.InvalidParameterCannotBeNilError("cancel")
	}
	if valid.IsNull(scope) {
		return nil, fail.InvalidParameterError("scope", "cannot be a null value of 'scopeapi.Scope'")
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

	xerr = task.SetID(id + scope.Description())
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
	ctx = context.WithValue(ctx, jobapi.KeyForJobInContext, nj) // nolint
	nj.ctx = ctx

	providerProfile, xerr := tenantfactory.FindProviderProfileForTenant(scope.Tenant())
	if xerr != nil {
		return nil, xerr
	}

	opts := []options.Option{}
	if providerProfile.Capabilities().UseTerraformer {
		config, xerr := prepareTerraformerConfiguration(providerProfile, scope)
		if xerr != nil {
			return nil, xerr
		}

		opts = append(opts, iaasoptions.WithTerraformer(config))
	}

	service, xerr := tenantfactory.UseService(ctx, opts...)
	if xerr != nil {
		return nil, xerr
	}

	nj.service = service
	xerr = register(nj)
	if xerr != nil {
		return nil, xerr
	}

	return nj, nil
}

// prepareTerraformerConfiguration assembles needed configuration to use terraform with the provider
func prepareTerraformerConfiguration(providerProfile *providers.Profile, scope scopeapi.Scope) (terraformerapi.Configuration, fail.Error) {
	if valid.IsNull(providerProfile) {
		return terraformerapi.Configuration{}, fail.InvalidParameterCannotBeNilError("providerProfile")
	}
	if valid.IsNull(scope) {
		return terraformerapi.Configuration{}, fail.InvalidParameterError("scope", "cannot be null value of '%s'", reflect.TypeOf(scope).String())
	}

	out := terraformerapi.Configuration{
		Release:           "= " + versions.Terraformv1_2_6.String(),
		WorkDir:           filepath.Join(global.Settings.Folders.TmpDir, "terraform", scope.FSPath()),
		ExecPath:          global.Settings.Backend.Terraform.ExecPath,
		PluginDir:         filepath.Join(global.Settings.Folders.ShareDir, "terraform", "plugins"),
		RequiredProviders: providerProfile.TerraformProviders(),
	}
	out.Consul.Prefix = "safescale/terraformstate/" + scope.KVPath()
	out.Consul.Server = "localhost:" + global.Settings.Backend.Consul.HttpPort
	return out, nil
}

// IsNull tells if the instance represents a null value
func (instance *job) IsNull() bool {
	return instance == nil || instance.uuid == ""
}

// ID returns the id of the job (ie the uuid of gRPC message)
func (instance *job) ID() string {
	if instance == nil {
		return ""
	}

	return instance.uuid
}

// Name returns the name (== id) of the job
func (instance *job) Name() string {
	if instance == nil {
		return ""
	}

	return instance.uuid
}

// Scope returns the Scope of the job
func (instance *job) Scope() scopeapi.Scope {
	if instance == nil {
		return nil
	}

	return instance.scope
}

// Context returns the context of the job (should be the same as the one of the task)
func (instance *job) Context() context.Context {
	if instance == nil {
		return context.Background()
	}

	return instance.ctx
}

// Task returns the task instance
func (instance *job) Task() concurrency.Task {
	if instance == nil {
		t, _ := concurrency.NewTask()
		return t
	}

	return instance.task
}

// Service returns the service instance
func (instance *job) Service() iaasapi.Service {
	if instance == nil {
		return nil
	}

	return instance.service
}

// Duration returns the duration of the job
func (instance *job) Duration() time.Duration {
	if instance == nil {
		return time.Duration(0)
	}

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
func (instance *job) Aborted() (bool, fail.Error) {
	if instance == nil {
		return false, fail.InvalidInstanceError()
	}
	status, err := instance.task.Status()
	if err != nil {
		return false, fail.Wrap(err, "problem getting aborted status")
	}
	return status == concurrency.ABORTED, nil
}

// Close tells the job to wait for end of operation; this ensures everything is cleaned up correctly
func (instance *job) Close() {
	if instance != nil {
		_ = deregister(instance.ID())
		if instance.cancel != nil {
			instance.cancel()
		}
		*instance = job{}
	}
}

// String returns a string representation of job information
func (instance *job) String() string {
	if instance == nil {
		return ""
	}
	return fmt.Sprintf("Job: %s (started at %s)", instance.scope.Description(), instance.startTime.String())
}

// register ...
func register(job jobapi.Job) fail.Error {
	if valid.IsNull(job) {
		return fail.InvalidParameterError("job", "cannot be null value of 'jobapi.Job'")
	}

	_, loaded := JobList.LoadOrStore(job.ID(), job)
	if loaded {
		return fail.DuplicateError("there is already a Job with ID '%s'", job.ID())
	}

	return nil
}

// deregister ...
func deregister(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	JobList.Delete(id)
	return nil
}

func init() {
	JobList = xsync.NewMapOf[jobapi.Job]()
}
