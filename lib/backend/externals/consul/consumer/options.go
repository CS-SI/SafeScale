package consumer

import (
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/hashicorp/consul/api"
)

// Option ...
type Option func(opt *settings) fail.Error

// WithPrefix ...
func WithPrefix(prefix string) Option {
	fn := func(c *settings) fail.Error {
		prefix = strings.Trim(strings.TrimSpace(prefix), "/")
		if prefix == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("prefix")
		}
		c.prefix = prefix
		return nil
	}
	return fn
}

// WithAddress ...
func WithAddress(address string) Option {
	return func(c *settings) fail.Error {
		address = strings.TrimSpace(address)
		if address == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("prefix")
		}
		c.consulConfig.Address = address
		return nil
	}
}

// WithAuth ...
func WithAuth(username, password string) Option {
	return func(c *settings) fail.Error {
		if username == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("username")
		}

		c.consulConfig.HttpAuth = &api.HttpBasicAuth{
			Username: username,
			Password: password,
		}
		return nil
	}
}

// WithToken ...
func WithToken(token string) Option {
	return func(c *settings) fail.Error {
		c.consulConfig.Token = token
		return nil
	}
}

// WithSessionTTL ...
func WithSessionTTL(ttl int) Option {
	return func(c *settings) fail.Error {
		if ttl <= 0 {
			return fail.InvalidParameterError("ttl", "must be > 0")
		}

		c.periodic = false
		c.ttl = ttl
		return nil
	}
}

// WithSessionPeriodicTTL ...
func WithSessionPeriodicTTL(ttl int) Option {
	return func(c *settings) fail.Error {
		if ttl <= 0 {
			return fail.InvalidParameterError("ttl", "must be > 0")
		}

		c.periodic = true
		c.ttl = ttl
		return nil
	}
}

// WithSessionName ...
func WithSessionName(name string) Option {
	return func(c *settings) fail.Error {
		c.sessionName = name
		return nil
	}
}

//
// // UseService ...
// func UseService(svc iaasapi.Service) Option {
// 	return func(c *settings) fail.Error {
// 		c.service = svc
// 		return nil
// 	}
// }
