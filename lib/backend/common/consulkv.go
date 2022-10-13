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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import (
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	consulapi "github.com/hashicorp/consul/api"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type ConsulKVClient struct {
	client *consulapi.Client
	kv     *consulapi.KV
	prefix string
}

// NewKVClient ...
func NewKVClient(prefix string) (*ConsulKVClient, fail.Error) {
	out := &ConsulKVClient{
		prefix: strings.Trim(strings.TrimSpace(prefix), "/"),
	}

	var err error
	config := &consulapi.Config{
		Datacenter: "safescale",
	}

	config.Address = "localhost:" + global.Settings.Backend.Consul.HttpPort
	out.client, err = consulapi.NewClient(config)
	if err != nil {
		return nil, fail.Wrap(err, "failed to instantiate a new Consul KV Client")
	}

	// Get a handle to the KV API
	out.kv = out.client.KV()
	return out, nil
}

// Put ...
func (cc *ConsulKVClient) Put(key string, value any) fail.Error {
	if valid.IsNull(cc) {
		return fail.InvalidInstanceError()
	}
	fullKey, xerr := cc.validateKey(key)
	if xerr != nil {
		return xerr
	}

	jsoned, err := json.Marshal(value)
	if err != nil {
		return fail.Wrap(err, "failed to marshal value")
	}

	// PUT a new KV pair
	p := &consulapi.KVPair{
		Key:   fullKey,
		Value: jsoned,
	}
	_, err = cc.kv.Put(p, nil)
	if err != nil {
		return fail.Wrap(err, "failed to put entry with key '%s'", key)
	}

	return nil
}

func (cc *ConsulKVClient) validateKey(key string) (string, fail.Error) {
	if key = strings.TrimSpace(key); key == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("key")
	}
	if strings.HasSuffix(key, "/") {
		return "", fail.InvalidParameterError("key", "does not contain a valid key ('/' is not allowed as last character)")
	}

	key = strings.Trim(key, "/")
	fullKey := cc.prefix
	if fullKey != "" {
		fullKey += "/"
	}
	fullKey += key
	return fullKey, nil
}

// Get ...
func (cc *ConsulKVClient) Get(key string) (out any, _ fail.Error) {
	if valid.IsNull(cc) {
		return out, fail.InvalidInstanceError()
	}
	fullKey, xerr := cc.validateKey(key)
	if xerr != nil {
		return nil, xerr
	}

	// Lookup the pair
	pair, _, err := cc.kv.Get(fullKey, nil)
	if err != nil {
		return nil, fail.Wrap(err, "failed to load value of key '%s'", key)
	}

	err = json.Unmarshal(pair.Value, &out)
	if err != nil {
		return nil, fail.Wrap(err, "failed to unmarshal value")
	}

	return out, nil
}

// Delete ...
func (cc *ConsulKVClient) Delete(key string) fail.Error {
	if valid.IsNull(cc) {
		return fail.InvalidInstanceError()
	}
	fullKey, xerr := cc.validateKey(key)
	if xerr != nil {
		return xerr
	}

	_, err := cc.kv.Delete(fullKey, nil)
	if err != nil {
		return fail.Wrap(err, "failed to delete key '%s'", key)
	}

	return nil
}

// CreateLock ...
func (cc *ConsulKVClient) CreateLock(key string) (*consulapi.Lock, fail.Error) {
	if valid.IsNull(cc) {
		return nil, fail.InvalidInstanceError()
	}
	fullKey, xerr := cc.validateKey(key)
	if xerr != nil {
		return nil, xerr
	}

	l, err := cc.client.LockKey(fullKey)
	if err != nil {
		return nil, fail.Wrap(err, "failed to create lock for key '%s'", key)
	}

	return l, nil
}
