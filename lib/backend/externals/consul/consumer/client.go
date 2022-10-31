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

package consumer

import (
	"strconv"
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type Client struct {
	client *consulapi.Client
	config *settings
}

// NewClient creates a new instance of consul Client
func NewClient(opts ...Option) (*Client, fail.Error) {
	config, xerr := newSettings(opts...)
	if xerr != nil {
		return nil, xerr
	}

	out := &Client{
		config: config,
	}

	var err error
	out.client, err = consulapi.NewClient(config.consulConfig)
	if err != nil {
		return nil, fail.Wrap(err, "failed to instantiate a new Consul KV Client")
	}

	return out, nil
}

func (instance *Client) IsNull() bool {
	return instance == nil || instance.client == nil || instance.config == nil
}

func (instance *Client) Agent() (*Agent, fail.Error) {
	if valid.IsNull(instance) {
		return nil, fail.InvalidParameterError("client", "cannot be null value of '*consul.consumer.Client'")
	}

	out := &Agent{
		client: instance,
		agent:  instance.client.Agent(),
	}
	return out, nil
}

func (instance *Client) NewKV(opts ...Option) (*KV, fail.Error) {
	if valid.IsNull(instance) {
		return nil, fail.InvalidParameterError("client", "cannot be null value of '*consul.consumer.Client'")
	}

	conf, xerr := mergeSettings(instance.config, opts...)
	if xerr != nil {
		return nil, xerr
	}

	prefix := strings.Trim(strings.TrimSpace(conf.prefix), "/")
	if prefix == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("prefix")
	}

	out := &KV{
		client:   instance,
		kv:       instance.client.KV(),
		prefix:   instance.config.prefix,
		lock:     &sync.RWMutex{},
		watchers: make(map[string]*watcher),
	}

	if conf.sessionName != "" {
		session, xerr := instance.newSession(*conf)
		if xerr != nil {
			return nil, xerr
		}

		out.session = session
	}

	return out, nil
}

func (instance *Client) newSession(conf settings) (_ *Session, ferr fail.Error) {
	if valid.IsNull(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// Defensive coding; should not happen
	if conf.ttl <= 0 {
		return nil, fail.InvalidRequestError("cannot use a ttl set to '%d'", conf.ttl)
	}

	entry := &consulapi.SessionEntry{
		Name:     conf.sessionName,
		Behavior: consulapi.SessionBehaviorRelease,
	}
	if conf.ttl > 0 {
		entry.TTL = strconv.Itoa(conf.ttl) + "s"
	}
	id, _, err := instance.client.Session().Create(entry, nil)
	if err != nil {
		logrus.Debugf("Error while creating session: %v", err)
		return nil, fail.Wrap(err)
	}
	defer func() {
		if ferr != nil {
			_, derr := instance.client.Session().Destroy(id, nil)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to destroy session"))
			}
		}
	}()

	out := &Session{
		session:   instance.client.Session(),
		lastEntry: entry,
		name:      conf.sessionName,
		id:        id,
		ttl:       conf.ttl,
		periodic:  conf.periodic,
	}

	if conf.periodic {
		xerr := out.Renew(WithSessionPeriodicTTL(conf.ttl))
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to set periodic renew of session")
		}
	}

	return out, nil
}
