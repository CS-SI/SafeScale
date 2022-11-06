package scope

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/common/scope/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/common/scope/internal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Load returns an existing scope from scope list
func Load(organization, project, tenant string) (scopeapi.Scope, fail.Error) {
	return internal.Load(organization, project, tenant)
}

// New creates a new scope
func New(organization, project, tenant, description string) (scopeapi.Scope, fail.Error) {
	return internal.New(organization, project, tenant, description)
}
