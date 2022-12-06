package abstract

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type (
	Option func(*core) fail.Error
)

// WithName defines the name of the resource (otherwise will be set to Unnamed)
func WithName(name string) Option {
	return func(c *core) fail.Error {
		if name == "" {
			return fail.InvalidParameterCannotBeNilError("name")
		}

		c.Name = name
		return nil
	}
}

// withKind defines the kind of the resource
func withKind(kind string) Option {
	return func(c *core) fail.Error {
		if kind == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("kind")
		}

		c.kind = kind
		return nil
	}
}

// UseTerraformSnippet ...
// UseTerraformSnippet allows to attach a snippet to the abstract resource
func UseTerraformSnippet(snippet string) Option {
	return func(c *core) fail.Error {
		if snippet == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("snippet")
		}

		c.terraformSnippet = snippet
		c.useTerraform = true
		return nil
	}
}

// WithResourceType ...
func WithResourceType(name string) Option {
	return func(c *core) fail.Error {
		if name == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("snippet")
		}

		c.terraformTypes = append(c.terraformTypes, name)
		c.useTerraform = true
		return nil
	}
}

func WithExtraData(name string, value any) Option {
	return func(c *core) fail.Error {
		if name == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("snippet")
		}

		c.extra[name] = value
		c.useTerraform = true
		return nil
	}
}

// MarkForCreation is used to mark resource as to be created
func MarkForCreation() Option {
	return WithExtraData(ExtraMarkedForCreation, true)
}

// MarkForDestruction is used to mark resource as to be destroyed
func MarkForDestruction() Option {
	return WithExtraData(ExtraMarkedForDestruction, true)
}
