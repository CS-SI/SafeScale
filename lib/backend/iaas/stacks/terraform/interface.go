package terraform

import (
	"embed"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type (
	ProviderInternals interface {
		providers.Provider

		GetEmbeddedFS() embed.FS
		Snippet() string
	}

	Resource interface {
		Snippet() string
	}

	Summoner interface {
		BuildMain(resource Resource) fail.Error
		Execute() (outputs any, ferr fail.Error)
	}
)
