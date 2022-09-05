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

package external

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

const (
	defaultHost string = "0.0.0.0" // By default, consul private server will listen on all interfaces
	defaultPort string = "58500"   // By default, consul private server will listen on port 58500
)

var (
	// go:embed consul.config.tmpl
	consulConfigTemplate string
	consulLauncher       sync.Once
)

// StartConsulServer creates consul configuration file if needed and starts consul agent in server mode
func StartConsulServer(ctx context.Context) (ferr fail.Error) {
	ferr = nil
	consulLauncher.Do(func() {
		// creates configuration if not present
		consulRootDir := global.Config.Folders.ShareDir + "consul"
		consulEtcDir := consulRootDir + "/etc"
		consulConfigFile := consulEtcDir + "/config.?"
		st, err := os.Stat(consulConfigFile)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				file, err := os.Create(consulConfigFile)
				if err != nil {
					ferr = fail.Wrap(err, "failed to create consul configuration file")
					return
				}

				_, err = file.WriteString(consulConfigTemplate)
				if err != nil {
					ferr = fail.Wrap(err, "failed to write content of consul configuration file")
					return
				}

				err = file.Close()
				if err != nil {
					ferr = fail.Wrap(err, "failed to close consul configuration file")
					return
				}
			} else {
				ferr = fail.Wrap(err)
				return
			}
		} else if st.IsDir() {
			ferr = fail.NotAvailableError("'%s' is a directory; should be a file", consulConfigFile)
			return
		}

		// Starts consul agent
		args := []string{"agent", "-config-dir=etc", "-server", "-datacenter=safescale"}
		attr := &os.ProcAttr{
			Sys: &syscall.SysProcAttr{
				Chroot: global.Config.Folders.ShareDir + "consul",
			},
		}
		proc, err := os.StartProcess(global.Config.Backend.Consul.ExecPath, args, attr)
		if err != nil {
			ferr = fail.Wrap(err, "failed to start consul server")
			return
		}

		var doneCh chan any

		waitConsulExitFunc := func(process *os.Process) {
			ps, err := process.Wait()
			if err != nil {
				ferr = fail.Wrap(err)
				doneCh <- ferr
				return
			}

			ws, ok := ps.Sys().(syscall.WaitStatus)
			if ok {
				doneCh <- ws
				return
			}

			doneCh <- ps.Sys()
		}

		waitConsulExitFunc(proc)

		select {
		case <-ctx.Done():
			proc.Signal(os.Interrupt)
			return
		case val := <-doneCh:
			switch casted := val.(type) {
			case int:
				logrus.Debugf("consul ends with status '%d'", casted)
			case *os.ProcessState:
				ferr = fail.NewError("consul exit with an unhandled state of type '%s': %v", reflect.TypeOf(casted).String(), casted)
			default:
				ferr = fail.NewError("consul exit with an unexpected state of type '%s': %v", reflect.TypeOf(val).String(), val)
			}
			return
		}
	})

	return ferr
}
