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
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
)

// Host links Object Storage folder and Network
type Host interface {
	Metadata
	Targetable

	Browse(task concurrency.Task, callback func(*abstract.HostCore) error) error                                           // Browse ...
	Create(task concurrency.Task, hostReq abstract.HostRequest, hostDef abstract.HostSizingRequirements) error             // Create creates a new host and its metadata
	WaitSSHReady(task concurrency.Task, timeout time.Duration) (status string, err error)                                  // WaitSSHReady ...
	SSHConfig(task concurrency.Task) (*system.SSHConfig, error)                                                            // SSHConfig loads SSH configuration for host from metadata
	Run(task concurrency.Task, cmd string, connectionTimeout, executionTimeout time.Duration) (int, string, string, error) // Run tries to execute command 'cmd' on the host
	Pull(task concurrency.Task, target, source string, timeout time.Duration) (int, string, string, error)                 // Pull downloads a file from host
	Push(task concurrency.Task, source, target, owner, mode string, timeout time.Duration) (int, string, string, error)    // Push uploads a file to ho
	Share(task concurrency.Task, shareRef string) (*propertiesv1.HostShare, error)                                         // Share returns a clone of the propertiesv1.HostShare corresponding to share 'shareRef'
	Start(task concurrency.Task) error                                                                                     // Start starts the host
	Stop(task concurrency.Task) error                                                                                      // Stop stops the host
	Reboot(task concurrency.Task) error                                                                                    // Reboot reboots the host
	Resize(hostSize abstract.HostSizingRequirements) error                                                                 // resize the host (probably not yet implemented on some proviers if not all)
	PublicIP(task concurrency.Task) (ip string, err error)                                                                 // PublicIP returns the public IP address of the host
	PrivateIP(task concurrency.Task) (ip string, err error)                                                                // PrivateIP returns the IP address of the host on the default local network
	PrivateIPOnNetwork(task concurrency.Task, networkID string) (ip string, err error)                                     // PrivateIPOnNetwork returns the IP address of the host on the local network requested
	AccessIP(task concurrency.Task) (string, error)                                                                        // GetAccessIP returns the IP to reach the host
	IsClusterMember(task concurrency.Task) (bool, error)                                                                   // IsClusterMember returns true if the host is member of a cluster
	PushStringToFile(task concurrency.Task, content string, filename string, owner, mode string) error                     // creates a file 'filename' on remote 'host' with the content 'content'
	DefaultNetwork(task concurrency.Task) (Network, error)                                                                 // returns the resources.Network object corresponding to the default network of the host
	State(task concurrency.Task) (hoststate.Enum, error)                                                                   // returns the current state of the host
	ToProtocol(task concurrency.Task) (protocol.Host, error)                                                               // Converts a host to equivalent gRPC message
}
