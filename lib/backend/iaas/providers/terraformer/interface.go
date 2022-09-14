package terraformer

import (
	"embed"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type (
	ProviderInternals interface {
		EmbeddedFS() embed.FS
		Snippet() string
	}

	Resource interface {
		Snippet() string
		ToMap() map[string]any
	}

	Summoner interface {
		Build(resource Resource) fail.Error
		Apply() (outputs any, ferr fail.Error)
		Destroy() (outputs any, ferr fail.Error)
		Plan() (outputs any, ferr fail.Error)
	}
)
