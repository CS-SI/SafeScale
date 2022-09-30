package job

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

const (
	KeyForJobInContext = "job"
)

// FromContext returns the job instance carried by the context
func FromContext(ctx context.Context) (Job, fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	jobInstance, ok := ctx.Value(KeyForJobInContext).(Job)
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

	if job, ok := jobMap[id]; ok {
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
	for uuid, job := range jobMap {
		listMap[uuid] = job.Name()
	}
	return listMap
}
