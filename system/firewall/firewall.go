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
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/system"
)

// Firewall implements a Firewall based on iptables
type Firewall struct {
	// Tables contains all the tables of the Firewall
	Tables map[string]*Table
}

// NewFirewall creates a new instance of Firewall and returns a pointer to it
func NewFirewall(ssh *system.SSHConfig) *Firewall {
	fw := Firewall{
		Tables: map[string]*Table{
			"filter": &Table{
				Name: "filter",
				Chains: map[string]*Chain{
					"INPUT": &Chain{
						Name: "INPUT",
					},
					"OUTPUT": &Chain{
						Name: "OUTPUT",
					},
					"FORWARD": &Chain{
						Name: "FORWARD",
					},
				},
			},
			"mangle": &Table{
				Name:   "mangle",
				Chains: nil,
			},
			"raw": &Table{
				Name:   "raw",
				Chains: nil,
			},
		},
	}
	return &fw
}

// FromSystem loads the current Firewall configuration from system
func (fw *Firewall) FromSystem() error {
	return fmt.Errorf("not yet implemented")
}

// Table returns the Table instance corresponding to table 'name'
func (fw *Firewall) Table(name string) (*Table, error) {
	name = strings.ToLower(name)
	var table *Table
	var ok bool
	if table, ok = fw.Tables[name]; !ok {
		return nil, fmt.Errorf("table '%s' not found in firewall", name)
	}
	return table, nil
}

// ToSystem applies the firewall rules to the host
func (fw *Firewall) ToSystem() error {
	return fmt.Errorf("not yet implemented")
}
