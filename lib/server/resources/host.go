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

package resources

import (
	"time"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
)

// Host links Object Storage folder and Network
type Host interface {
	Metadata
	Targetable

	// Browse ...
	Browse(task concurrency.Task, callback func(*abstracts.Host) error) error
	// Create creates a new host and its metadata
	Create(task concurrency.Task, hostReq abstracts.HostRequest, hostDef abstracts.SizingRequirements) error
	// WaitSSHReady ...
	WaitSSHReady(task concurrency.Task, timeout time.Duration) (status string, err error)
	// SSHConfig loads SSH configuration for host from metadata
	SSHConfig(task concurrency.Task) (*system.SSHConfig, error)
	// Run tries to execute command 'cmd' on the host
	Run(task concurrency.Task, cmd string, connectionTimeout, executionTimeout time.Duration) (int, string, string, error)
	// Pull downloads a file from host
	Pull(task concurrency.Task, target, source string, timeout time.Duration) (int, string, string, error)
	// Push uploads a file to ho
	Push(task concurrency.Task, source, target string, timeout time.Duration) (int, string, string, error)
	// Share returns a clone of the propertiesv1.HostShare corresponding to share 'shareRef'
	Share(task concurrency.Task, shareRef string) (*propertiesv1.HostShare, error)
	// Start starts the host
	Start(task concurrency.Task) error
	// Stop stops the host
	Stop(task concurrency.Task) error
	// Reboot reboots the host
	Reboot(task concurrency.Task) error
	// Resize ...
	Resize(hostSize abstracts.SizingRequirements) error
	// PublicIP returns the public IP address of the host
	PublicIP(task concurrency.Task) (ip string, err error)
	// PrivateIP ...
	PrivateIP(task concurrency.Task) (ip string, err error)
	// GetAccessIP returns the IP to reach the host
	AccessIP(task concurrency.Task) (string, error)
	// IsClusterMember returns true if the host is member of a cluster
	IsClusterMember(task concurrency.Task) (bool, error)
	// PushStringToFile creates a file 'filename' on remote 'host' with the content 'content'
	PushStringToFile(task concurrency.Task, content string, filename string, owner, group, rights string) error
	DefaultNetwork(task concurrency.Task) (Network, error)

	ToProtocolHost() *protocol.Host
}
