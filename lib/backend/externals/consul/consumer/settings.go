package consumer

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	consulapi "github.com/hashicorp/consul/api"
)

// settings ...
type settings struct {
	consulConfig *consulapi.Config
	prefix       string // prefix for KV
	address      string // address of the agent
	sessionName  string // name of the session to use (if set)
	sessionID    string // id of the session to use (if set)
	ttl          int    // set the ttl (in seconds) for a session (being periodic or not)
	periodic     bool   // set to true for a session that needs periodic renew
	// service      iaasapi.Service
}

// newSettings ...
func newSettings(opts ...Option) (*settings, fail.Error) {
	c := &settings{
		consulConfig: consulapi.DefaultConfig(),
	}

	for _, v := range opts {
		xerr := v(c)
		if xerr != nil {
			return nil, xerr
		}
	}

	return c, nil
}

func mergeSettings(in *settings, opts ...Option) (*settings, fail.Error) {
	out := new(settings)
	*out = *in

	for _, v := range opts {
		xerr := v(out)
		if xerr != nil {
			return nil, xerr
		}
	}

	return out, nil
}
