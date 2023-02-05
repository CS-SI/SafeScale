package api

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
)

const OptionTargets = "targets"

func WithTarget(rsc abstract.Abstract) options.Option {
	return func(o options.Options) fail.Error {
		if rsc == nil {
			return fail.InvalidParameterCannotBeEmptyStringError("rsc")
		}

		var targets []string
		value, xerr := o.Load(OptionTargets)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// continue
				targets = []string{}
			default:
				return xerr
			}
		} else {
			var err error
			targets, err = lang.Cast[[]string](value)
			if err != nil {
				return fail.Wrap(err)
			}
		}

		return o.Store("targets", targets)
	}
}
