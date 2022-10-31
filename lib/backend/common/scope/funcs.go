package scope

import (
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// Resource returns the resource corresponding to key (being an id or a name)
func Resource[T resources.Core](scope *Frame, kind string, ref string) (T, fail.Error) {
	var empty T
	if valid.IsNull(scope) {
		return empty, fail.InvalidInstanceError()
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return empty, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	index := kind + ":" + ref
	id, found := scope.resourceByName.Load(ref)
	if found {
		index = kind + ":" + id
	}

	rsc, found := scope.resourceByID.Load(index)
	if found {
		out, ok := rsc.(T)
		if ok {
			return out, nil
		}
	}

	return empty, fail.NotFoundError("failed to find resource identified by %s", ref)
}
