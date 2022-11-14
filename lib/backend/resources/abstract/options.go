package abstract

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type (
	Option func(*Core) fail.Error
)

// WithName defines the name of the resource (otherwise will be set to "unnamed")
func WithName(name string) Option {
	return func(c *Core) fail.Error {
		if name == "" {
			c.Name = Unnamed
		} else {
			c.Name = name
		}
		return nil
	}
}

// withKind defines the kind of the resource
func withKind(kind string) Option {
	return func(c *Core) fail.Error {
		if kind == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("kind")
		}

		c.kind = kind
		return nil
	}
}

// UseTerraformSnippet allows to attach a snippet to the abstract resource
func UseTerraformSnippet(snippet string) Option {
	return func(c *Core) fail.Error {
		if snippet == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("snippet")
		}

		c.terraformSnippet = snippet
		c.useTerraform = true
		return nil
	}
}
