/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package metadata

import (
	"strings"

	scopeapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/scope/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/consul/consumer"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata/storage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata/storage/bucket"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata/storage/consul"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	MethodObjectStorage = "objectstorage"
	MethodConsul        = "consul"

	OptionUseMethodKey     = "method"
	OptionWithPrefixKey    = "prefix"
	OptionWithScopeKey     = "scope"
	OptionWithoutReloadKey = "no_reload"
)

type config struct {
	method   string
	prefix   string
	scope    scopeapi.Scope
	consulKV *consumer.KV
	noReload bool
}

// type Option func(*config) fail.Error

// UseMethod defines the method used to store metadata
func UseMethod(method string) options.Option {
	return func(opts options.Options) fail.Error {
		method = strings.TrimSpace(method)
		if method == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("method")
		}

		switch method {
		case MethodObjectStorage, MethodConsul:
		default:
			return fail.InvalidParameterError(OptionUseMethodKey, "invalid value '%s'", method)
		}

		return opts.Store(OptionUseMethodKey, method)
	}
}

// WithPrefix allows to define the prefix use by the folder
func WithPrefix(prefix string) options.Option {
	return func(c options.Options) fail.Error {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("prefix")
		}

		return c.Store(OptionWithPrefixKey, prefix)
	}
}

// WithScope allows to attach the corresponding scope
func WithScope(scope scopeapi.Scope) options.Option {
	return func(o options.Options) fail.Error {
		if valid.IsNull(scope) {
			return fail.InvalidParameterError("svc", "cannot be null value of 'scopeapi.Scope'")
		}

		return o.Store(OptionWithScopeKey, scope)
	}
}

// func WithConsul(kv *consumer.KV) Option {
// 	return func(c *config) fail.Error {
// 		if valid.IsNull(kv) {
// 			return fail.InvalidParameterError("kv", "cannot be null value of '*consul.consumer.KV'")
// 		}
//
// 		c.consulKV = kv
// 		return nil
// 	}
// }

// WithoutReload tells to not reload, on Alter/Inspect
func WithoutReload() func(options.Options) fail.Error {
	return func(opts options.Options) fail.Error {
		return opts.Store(OptionWithoutReloadKey, true)
	}
}

// NewFolder creates a Folder corresponding to the method wanted
func NewFolder(opts ...options.Option) (storage.Folder, fail.Error) {
	o, xerr := options.New(opts...)
	if xerr != nil {
		return nil, xerr
	}

	method, xerr := options.Value[string](o, OptionUseMethodKey)
	if xerr != nil {
		return nil, xerr
	}

	scope, xerr := options.Value[scopeapi.Scope](o, OptionWithScopeKey)
	if xerr != nil {
		return nil, xerr
	}

	prefix, xerr := options.Value[string](o, OptionWithPrefixKey)
	if xerr != nil {
		return nil, xerr
	}

	if prefix == "" {
		return nil, fail.InvalidRequestError("invalid use of empty 'prefix'")
	}
	if valid.IsNull(scope) {
		return nil, fail.InvalidRequestError("cannot create new folder using Consul KV without a valid scope")
	}

	switch method {
	case MethodObjectStorage:
		return bucket.NewFolder(scope.Service(), prefix)
	case MethodConsul:
		// consulClient, xerr := consumer.NewClient(consumer.WithAddress("localhost:" + global.Settings.Backend.Consul.HttpPort))
		// if xerr != nil {
		// 	return nil, xerr
		// }
		//
		// opts := []consumer.Option{
		// 	consumer.WithAddress("localhost:" + global.Settings.Backend.Consul.HttpPort),
		// 	consumer.WithPrefix(cfg.prefix),
		// }
		// kv, xerr := consulClient.NewKV(opts...)
		return consul.NewFolder(scope, prefix)

	default:
		return nil, fail.InvalidRequestError("method", "method '%s' is unsupported", method)
	}
}
