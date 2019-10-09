//+build libvirt

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

package local

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// VMInfo represents the useful informations package send from each new local vm
type VMInfo struct {
	publicIP string
}

// VMInfoWaiterStruct represents the golbal info waiter
type VMInfoWaiterStruct struct {
	listner     *net.Listener
	port        int
	chansByName map[string](chan VMInfo)
	mutex       sync.Mutex
}

var vmInfoWaiter = VMInfoWaiterStruct{
	chansByName: map[string](chan VMInfo){},
}

// Register will register a vmCreator who wants to be notified if the listener receives information of the vm he created
func (iw *VMInfoWaiterStruct) Register(name string) chan VMInfo {
	channel := make(chan VMInfo)

	iw.mutex.Lock()
	iw.chansByName[name] = channel
	iw.mutex.Unlock()
	fmt.Println("Registered : ", name)

	return channel
}

func (iw *VMInfoWaiterStruct) deregister(name string) error {
	iw.mutex.Lock()
	channel, found := iw.chansByName[name]
	if found {
		delete(iw.chansByName, name)
		close(channel)
	}
	iw.mutex.Unlock()

	if !found {
		return fmt.Errorf("nothing registered with the name %s", name)
	}
	fmt.Println("Deregistered : ", name)
	return nil
}

// GetInfoWaiter get the global var vmInfoWaiter and setup the listner if it is not set
func GetInfoWaiter() (*VMInfoWaiterStruct, error) {
	if vmInfoWaiter.listner == nil {
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			return nil, fmt.Errorf("failed to open a tcp connection : %s", err.Error())
		}
		vmInfoWaiter.port = listener.Addr().(*net.TCPAddr).Port
		vmInfoWaiter.listner = &listener
		fmt.Printf("InfoWaiter created on port %d", vmInfoWaiter.port)

		go infoHandler()
	}

	return &vmInfoWaiter, nil
}

func infoHandler() {
	for {
		conn, err := (*vmInfoWaiter.listner).Accept()
		if err != nil {
			panic(fmt.Sprintf("Info handler, Error accepting: %s", err.Error()))
		}

		go func(net.Conn) {
			defer func() {
				if err := conn.Close(); err != nil {
					fmt.Printf("failed to close the tcp connection: %s", err.Error())
				}
			}()

			buffer := make([]byte, 1024)

			nbChars, err := conn.Read(buffer)
			if err != nil {
				panic(fmt.Sprintf("Info handler, Error reading: %s", err.Error()))
			}

			message := string(buffer[0:nbChars])
			message = strings.Trim(message, "\n")
			fmt.Println("Info readed : ", message)
			splittedMessage := strings.Split(message, "|")
			hostName := splittedMessage[0]
			ip := splittedMessage[1]
			info := VMInfo{
				publicIP: ip,
			}
			vmInfoWaiter.mutex.Lock()
			channel, found := vmInfoWaiter.chansByName[hostName]
			vmInfoWaiter.mutex.Unlock()
			if !found {
				panic(fmt.Sprintf("Info handler, Received info from an unregistered host: %s", message))
			}
			channel <- info
			err = vmInfoWaiter.deregister(hostName)
			if err != nil {
				panic(fmt.Sprintf("Info handler, Error deregistering: %s", err.Error()))
			}
		}(conn)
	}
}
