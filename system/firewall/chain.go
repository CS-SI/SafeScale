/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"sync"

	"github.com/CS-SI/SafeScale/system/firewall/Policy"
)

// Chain ...
type Chain struct {
	Name   string
	Policy Policy.Enum
	Rules  []Rule
	lock   sync.RWMutex
}

// Add appends a rule at the end in the chain
func (c *Chain) Add(rule Rule) *Chain {
	c.lock.Lock()
	c.Rules = append(c.Rules, rule)
	c.lock.Unlock()
	return c
}

// Insert adds a rule at the beginning of the chain
func (c *Chain) Insert(rule Rule) *Chain {
	c.lock.Lock()
	c.Rules = append([]Rule{rule}, c.Rules...)
	c.lock.Unlock()
	return c
}

// Remove a rule from the chain
func (c *Chain) Remove(rule Rule) *Chain {
	return c
}

// RemoveIndex removes a rule by its index in the chain
func (c *Chain) RemoveIndex(idx uint) *Chain {
	return c
}
