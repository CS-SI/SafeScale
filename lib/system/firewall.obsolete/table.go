/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package firewall

import (
	"fmt"
	"sync"

	"github.com/CS-SI/SafeScale/lib/system/firewall.obsolete/policy"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// Table defines a table of the firewall
type Table struct {
	Name   string
	Chains map[string]*Chain
	lock   sync.RWMutex
}

// NewChain creates a new
func (t *Table) NewChain(name string, p policy.Enum) *Chain {
	chain := Chain{
		Name:   name,
		Policy: p,
	}
	t.Chains[name] = &chain
	return &chain
}

// Chain returns the chain named 'name'
func (t *Table) Chain(name string) (*Chain, error) {
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty!")
	}
	var chain *Chain
	var found bool
	if chain, found = t.Chains[name]; !found {
		return nil, fmt.Errorf("table '%s' doesn't contain a chain '%s'", t.Name, name)
	}
	return chain, nil
}
