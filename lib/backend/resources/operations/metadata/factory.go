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

	"github.com/CS-SI/SafeScale/v22/lib/backend/common/scope"
	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/consul/consumer"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/metadata/storage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/metadata/storage/bucket"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/metadata/storage/consul"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	MethodObjectStorage = "objectstorage"
	MethodConsul        = "consul"
)

type config struct {
	method   string
	prefix   string
	frame    *scope.Frame
	consulKV *consumer.KV
	noReload bool
}

type Option func(*config) fail.Error

// UseMethod defines the method used to store metadata
func UseMethod(method string) Option {
	return func(c *config) fail.Error {
		method = strings.TrimSpace(method)
		if method == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("method")
		}

		switch method {
		case MethodObjectStorage, MethodConsul:
		default:
			return fail.InvalidParameterError("method", "invalid value '%s'", method)
		}

		c.method = method
		return nil
	}
}

// WithPrefix allows to define the prefix use by the folder
func WithPrefix(prefix string) Option {
	return func(c *config) fail.Error {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("prefix")
		}

		c.prefix = prefix
		return nil
	}
}

// WithScope allows to attach the corresponding scope
func WithScope(scope *scope.Frame) Option {
	return func(c *config) fail.Error {
		if valid.IsNull(scope) {
			return fail.InvalidParameterError("svc", "cannot be null value of '*scope.Frame'")
		}

		c.frame = scope
		return nil
	}
}

// WithFrame is an alias of WithScope
func WithFrame(frame *scope.Frame) Option {
	return WithScope(frame)
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
func WithoutReload() func(*config) fail.Error {
	return func(c *config) fail.Error {
		c.noReload = true
		return nil
	}
}

// NewFolder creates a Folder corresponding to the method wanted
func NewFolder(opts ...Option) (storage.Folder, fail.Error) {
	cfg := config{}
	for _, v := range opts {
		xerr := v(&cfg)
		if xerr != nil {
			return nil, xerr
		}
	}

	switch cfg.method {
	case MethodObjectStorage:
		return bucket.NewFolder(cfg.frame.Service(), cfg.prefix)
	case MethodConsul:
		if cfg.prefix == "" {
			return nil, fail.InvalidRequestError("invalid use of empty 'prefix'")
		}
		if valid.IsNull(cfg.frame) {
			return nil, fail.InvalidRequestError("cannot create new folder using Consul KV without a valid scope")
		}

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
		return consul.NewFolder(cfg.frame.ConsulKV(), cfg.prefix)

	default:
		return nil, fail.InvalidRequestError("method", "method '%s' is unsupported", cfg.method)
	}
}
