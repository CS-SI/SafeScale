package iaasoptions

import (
	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	OptionScope = "scope"
)

// WithScope allows to indicate what scope is used
func WithScope(scope terraformerapi.ScopeLimitedToTerraformerUse) options.Option {
	return func(o options.Options) fail.Error {
		if valid.IsNull(scope) {
			return fail.InvalidParameterError("scope", "must be a valid 'scopeapi.Scope'")
		}

		return options.Add(o, OptionScope, scope)
	}
}
