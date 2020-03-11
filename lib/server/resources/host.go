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
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

// Host links Object Storage folder and Network
type Host interface {
	Metadata
	Targetable
	data.NullValue

	Browse(task concurrency.Task, callback func(*abstract.HostCore) error) error                               // ...
	Create(task concurrency.Task, hostReq abstract.HostRequest, hostDef abstract.HostSizingRequirements) error // creates a new host and its metadata
	GetAccessIP(task concurrency.Task) (string, error)                                                         // returns the IP to reach the host, with error handling
	GetDefaultNetwork(task concurrency.Task) (Network, error)                                                  // returns the resources.Network object corresponding to the default network of the host, with error handling
	GetMounts(task concurrency.Task) (*propertiesv1.HostMounts, error)                                         // returns the mounts on the host
	GetPrivateIP(task concurrency.Task) (ip string, err error)                                                 // returns the IP address of the host on the default local network, with error handling
	GetPrivateIPOnNetwork(task concurrency.Task, networkID string) (ip string, err error)                      // returns the IP address of the host on the local network requested, with error handling
	GetPublicIP(task concurrency.Task) (ip string, err error)                                                  // returns the public IP address of the host, with error handling
	GetShare(task concurrency.Task, shareRef string) (*propertiesv1.HostShare, error)                          // returns a clone of the propertiesv1.HostShare corresponding to share 'shareRef'
	GetShares(task concurrency.Task) (*propertiesv1.HostShares, error)                                         // returns the shares hosted on the host
	GetSSHConfig(task concurrency.Task) (*system.SSHConfig, error)                                             // loads SSH configuration for host from metadata
	GetState(task concurrency.Task) (hoststate.Enum, error)                                                    // returns the current state of the host, with error handling
	GetVolumes(task concurrency.Task) (*propertiesv1.HostVolumes, error)
	IsClusterMember(task concurrency.Task) (bool, error)                                                                                      // returns true if the host is member of a cluster
	Pull(task concurrency.Task, target, source string, timeout time.Duration) (int, string, string, error)                                    // downloads a file from host
	Push(task concurrency.Task, source, target, owner, mode string, timeout time.Duration) (int, string, string, error)                       // uploads a file to host
	PushStringToFile(task concurrency.Task, content string, filename string, owner, mode string) error                                        // creates a file 'filename' on remote 'host' with the content 'content'
	Reboot(task concurrency.Task) error                                                                                                       // reboots the host
	Resize(hostSize abstract.HostSizingRequirements) error                                                                                    // resize the host (probably not yet implemented on some proviers if not all)
	Run(task concurrency.Task, cmd string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (int, string, string, error) // tries to execute command 'cmd' on the host
	SafeGetPublicIP(task concurrency.Task) string                                                                                             // returns the public IP address of the host, without error handling (returning "" if cannot be defined)
	SafeGetPrivateIP(task concurrency.Task) string                                                                                            // returns the IP address of the host on the default local network, without error handling (returning "" if cannot be defined)
	SafeGetPrivateIPOnNetwork(task concurrency.Task, networkID string) string                                                                 // returns the IP address of the host on the local network requested, , without error handling (returning "" if cannot be defined)
	SafeGetAccessIP(task concurrency.Task) string                                                                                             // returns the IP to reach the host, , without error handling (returning "" if cannot be defined)
	SafeGetState(task concurrency.Task) hoststate.Enum                                                                                        // returns the latest retrieved state of the host, without error handling
	Start(task concurrency.Task) error                                                                                                        // starts the host
	Stop(task concurrency.Task) error                                                                                                         // stops the host
	ToProtocol(task concurrency.Task) (*protocol.Host, error)                                                                                 // converts a host to equivalent gRPC message
	WaitSSHReady(task concurrency.Task, timeout time.Duration) (status string, err error)                                                     // WaitSSHReady ...
}
