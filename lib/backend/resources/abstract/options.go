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
	return func(c *core) fail.Error {
		xerr := WithExtraData(ExtraMarkedForCreation, true)(c)
		if xerr != nil {
			return xerr
		}

		return WithExtraData(ExtraMarkedForDestruction, false)(c)
	}
}

// ClearMarkForCreation is used to "unmark" resource as to be created
func ClearMarkForCreation() Option {
	return func(c *core) fail.Error {
		return WithExtraData(ExtraMarkedForCreation, false)(c)
	}
}

// MarkForDestruction is used to mark resource as to be destroyed
func MarkForDestruction() Option {
	return func(c *core) fail.Error {
		xerr := WithExtraData(ExtraMarkedForCreation, false)(c)
		if xerr != nil {
			return xerr
		}

		return WithExtraData(ExtraMarkedForDestruction, true)(c)
	}
}

func MarkAsStarted() Option {
	return WithExtraData("WantedHostState", wantedHostStarted)
}

func MarkAsStopped() Option {
	return WithExtraData("WantedHostState", wantedHostStopped)
}
