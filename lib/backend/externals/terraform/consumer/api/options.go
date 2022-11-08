package api

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
)

const OptionTargets = "targets"

func WithTarget(name string) options.Option {
	return func(o options.Options) fail.Error {
		if name == "" {
			return fail.InvalidParameterCannotBeEmptyStringError(name)
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
		targets = append(targets, name)
		return o.Store("targets", targets)
	}
}
