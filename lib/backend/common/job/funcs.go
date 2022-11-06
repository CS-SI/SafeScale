package job

import (
	"context"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/common/job/internal"
	scopeapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/scope/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// New creates a new instance of struct Job
func New(ctx context.Context, cancel context.CancelFunc, scope scopeapi.Scope) (_ jobapi.Job, ferr fail.Error) { // nolint
	return internal.New(ctx, cancel, scope)
}

// FromContext returns the job instance carried by the context
func FromContext(ctx context.Context) (jobapi.Job, fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	jobInstance, ok := ctx.Value(jobapi.KeyForJobInContext).(jobapi.Job)
	if !ok {
		return nil, fail.InconsistentError("value in context must satisfy interface 'Job'")
	}

	return jobInstance, nil
}

// AbortByID asks the job identified by 'id' to abort
func AbortByID(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	if job, ok := internal.JobList.Load(id); ok {
		if xerr := job.Abort(); xerr != nil {
			return fail.Wrap(xerr, "failed to stop job '%s'", id)
		}
		return nil
	}
	return fail.NotFoundError("no job identified by '%s' found", id)
}

// List ...
func List() map[string]string {
	listMap := map[string]string{}
	internal.JobList.Range(func(key string, value jobapi.Job) bool {
		listMap[key] = value.Name()
		return true
	})
	return listMap
}
