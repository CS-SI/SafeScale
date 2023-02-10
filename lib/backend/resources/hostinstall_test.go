//go:build fixme
// +build fixme

//FIXME: need to move NewServiceTest inside a package

/*
* Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"runtime"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/stretchr/testify/require"
)

func TestHost_AddFeature(t *testing.T) {

	var ohost *Host = nil
	ctx := context.Background()

	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	// Wrong *Host instance
	_, xerr = ohost.AddFeature(ctx, "ansible", data.Map{}, FeatureSettings{})
	require.Contains(t, xerr.Error(), "calling method from a nil pointer")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, _, xerr := svc.CreateHost(ctx, abstract.HostRequest{
			ResourceName:   "MyHostTest",
			HostName:       "MyHostTest",
			ImageID:        "ImageID",
			PublicIP:       true,
			Single:         true,
			Subnets:        []*abstract.Subnet{},
			DefaultRouteIP: "127.0.0.1",
			DiskSize:       64,
			TemplateID:     "TemplateID",
		})
		require.Nil(t, xerr)

		host, xerr := LoadHost(ctx, svc, "MyHostTest")
		require.Nil(t, xerr)
		ohost = host.(*Host)

		// Wrong ctx
		_, xerr = ohost.AddFeature(nil, "ansible", data.Map{}, FeatureSettings{}) // nolint
		require.Contains(t, xerr.Error(), "invalid parameter: ctx")

		// Wrong name
		_, xerr = ohost.AddFeature(ctx, "", data.Map{}, FeatureSettings{})
		require.Contains(t, xerr.Error(), "invalid parameter: name")

		// Host not stared
		_, xerr = ohost.AddFeature(ctx, "ansible", data.Map{}, FeatureSettings{})
		require.Contains(t, xerr.Error(), "cannot install feature on 'MyHostTest', 'MyHostTest' is NOT started")

		xerr = host.Start(ctx)
		require.Nil(t, xerr)

		svc._setLogLevel(1)
		_, xerr = ohost.AddFeature(ctx, "ansible", data.Map{}, FeatureSettings{})
		require.Nil(t, xerr)

	})
	require.Nil(t, err)

}

func TestHost_CheckFeature(t *testing.T) {

	var ohost *Host = nil
	ctx := context.Background()

	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	// Wrong *Host instance
	_, xerr = ohost.CheckFeature(ctx, "ansible", data.Map{}, FeatureSettings{})
	require.Contains(t, xerr.Error(), "calling method from a nil pointer")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, _, xerr := svc.CreateHost(ctx, abstract.HostRequest{
			ResourceName:   "MyHostTest",
			HostName:       "MyHostTest",
			ImageID:        "ImageID",
			PublicIP:       true,
			Single:         true,
			Subnets:        []*abstract.Subnet{},
			DefaultRouteIP: "127.0.0.1",
			DiskSize:       64,
			TemplateID:     "TemplateID",
		})
		require.Nil(t, xerr)

		host, xerr := LoadHost(ctx, svc, "MyHostTest")
		require.Nil(t, xerr)
		ohost = host.(*Host)

		// Wrong ctx
		_, xerr = ohost.CheckFeature(nil, "ansible", data.Map{}, FeatureSettings{}) // nolint
		require.Contains(t, xerr.Error(), "invalid parameter: ctx")

		// Wrong name
		_, xerr = ohost.CheckFeature(ctx, "", data.Map{}, FeatureSettings{})
		require.Contains(t, xerr.Error(), "invalid parameter: featureName")

		// Host not stared
		_, xerr = ohost.CheckFeature(ctx, "ansible", data.Map{}, FeatureSettings{})
		require.Contains(t, xerr.Error(), "cannot check feature on 'MyHostTest', 'MyHostTest' is NOT started")

		xerr = host.Start(ctx)
		require.Nil(t, xerr)

		svc._setLogLevel(1)
		_, xerr = ohost.CheckFeature(ctx, "ansible", data.Map{}, FeatureSettings{})
		require.Nil(t, xerr)

	})
	require.Nil(t, err)

}

func TestHost_DeleteFeature(t *testing.T) {

	var ohost *Host = nil
	ctx := context.Background()

	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	// Wrong *Host instance
	_, xerr = ohost.DeleteFeature(ctx, "ansible", data.Map{}, FeatureSettings{})
	require.Contains(t, xerr.Error(), "invalid instance: in function")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, _, xerr := svc.CreateHost(ctx, abstract.HostRequest{
			ResourceName:   "MyHostTest",
			HostName:       "MyHostTest",
			ImageID:        "ImageID",
			PublicIP:       true,
			Single:         true,
			Subnets:        []*abstract.Subnet{},
			DefaultRouteIP: "127.0.0.1",
			DiskSize:       64,
			TemplateID:     "TemplateID",
		})
		require.Nil(t, xerr)

		host, xerr := LoadHost(ctx, svc, "MyHostTest")
		require.Nil(t, xerr)
		ohost = host.(*Host)

		// Wrong ctx
		_, xerr = ohost.DeleteFeature(nil, "ansible", data.Map{}, FeatureSettings{}) // nolint
		require.Contains(t, xerr.Error(), "invalid parameter: inctx")

		// Wrong name
		_, xerr = ohost.DeleteFeature(ctx, "", data.Map{}, FeatureSettings{})
		require.Contains(t, xerr.Error(), "invalid parameter: featureName")

		// Host not stared
		_, xerr = ohost.DeleteFeature(ctx, "ansible", data.Map{}, FeatureSettings{})
		require.Contains(t, xerr.Error(), "cannot Delete feature on 'MyHostTest', 'MyHostTest' is NOT started")

		xerr = host.Start(ctx)
		require.Nil(t, xerr)

		svc._setLogLevel(1)

		_, xerr = ohost.DeleteFeature(ctx, "ansible", data.Map{}, FeatureSettings{})
		require.Nil(t, xerr)

	})
	require.Nil(t, err)

}

func TestHost_TargetType(t *testing.T) {

	var ohost *Host = nil
	result := ohost.TargetType()
	require.EqualValues(t, result.String(), "Unknown")

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, _, xerr := svc.CreateHost(ctx, abstract.HostRequest{
			ResourceName:   "MyHostTest",
			HostName:       "MyHostTest",
			ImageID:        "ImageID",
			PublicIP:       true,
			Single:         true,
			Subnets:        []*abstract.Subnet{},
			DefaultRouteIP: "127.0.0.1",
			DiskSize:       64,
			TemplateID:     "TemplateID",
		})
		require.Nil(t, xerr)

		host, xerr := LoadHost(ctx, svc, "MyHostTest")
		require.Nil(t, xerr)
		ohost = host.(*Host)

		svc._setLogLevel(2)

		result = ohost.TargetType()
		require.EqualValues(t, result.String(), "Host")

	})
	require.Nil(t, err)

}

func TestHost_InstallMethods(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ohost *Host = nil
	_, xerr = ohost.InstallMethods(ctx)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, _, xerr := svc.CreateHost(ctx, abstract.HostRequest{
			ResourceName:   "MyHostTest",
			HostName:       "MyHostTest",
			ImageID:        "ImageID",
			PublicIP:       true,
			Single:         true,
			Subnets:        []*abstract.Subnet{},
			DefaultRouteIP: "127.0.0.1",
			DiskSize:       64,
			TemplateID:     "TemplateID",
		})
		require.Nil(t, xerr)

		host, xerr := LoadHost(ctx, svc, "MyHostTest")
		require.Nil(t, xerr)
		ohost = host.(*Host)

		xerr = host.Start(ctx)
		require.Nil(t, xerr)

		_, xerr = ohost.AddFeature(ctx, "ansible", data.Map{}, FeatureSettings{})
		require.Nil(t, xerr)

		svc._setLogLevel(2)

		methods, xerr := ohost.InstallMethods(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, methods[1], installmethod.Bash)
		require.EqualValues(t, methods[2], installmethod.None)

	})
	require.Nil(t, err)

}

func TestHost_RegisterFeature(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, _, xerr := svc.CreateHost(ctx, abstract.HostRequest{
			ResourceName:   "MyHostTest",
			HostName:       "MyHostTest",
			ImageID:        "ImageID",
			PublicIP:       true,
			Single:         true,
			Subnets:        []*abstract.Subnet{},
			DefaultRouteIP: "127.0.0.1",
			DiskSize:       64,
			TemplateID:     "TemplateID",
		})
		require.Nil(t, xerr)

		host, xerr := LoadHost(ctx, svc, "MyHostTest")
		require.Nil(t, xerr)
		ohost := host.(*Host)

		feat, xerr := NewFeature(ctx, svc, "ansible")
		require.Nil(t, xerr)

		xerr = ohost.RegisterFeature(ctx, feat, nil, false)
		require.Nil(t, xerr)

		xerr = ohost.UnregisterFeature(ctx, "ansible")
		require.Nil(t, xerr)

		// FIXME: can unregister not registred feature ?
		xerr = ohost.UnregisterFeature(ctx, "ansible")
		require.Nil(t, xerr)

	})
	require.Nil(t, err)

}

func TestHost_ListEligibleFeatures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}

	var ohost *Host = nil

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	_, xerr = ohost.ListEligibleFeatures(ctx)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, _, xerr := svc.CreateHost(ctx, abstract.HostRequest{
			ResourceName:   "MyHostTest",
			HostName:       "MyHostTest",
			ImageID:        "ImageID",
			PublicIP:       true,
			Single:         true,
			Subnets:        []*abstract.Subnet{},
			DefaultRouteIP: "127.0.0.1",
			DiskSize:       64,
			TemplateID:     "TemplateID",
		})
		require.Nil(t, xerr)

		host, xerr := LoadHost(ctx, svc, "MyHostTest")
		require.Nil(t, xerr)
		ohost := host.(*Host)

		svc._setLogLevel(2)

		list, xerr := ohost.ListEligibleFeatures(ctx)
		if xerr == nil {
			require.Nil(t, xerr)
			require.Greater(t, len(list), 0)
			for index := range list {
				fn, _ := list[index].GetFilename(ctx)
				t.Logf("[%d] %s > %s", index, list[index].GetName(), fn)
			}
		} else {
			t.Skip()
		}
	})
	require.Nil(t, err)

}

func TestHost_ListInstalledFeatures(t *testing.T) {

	var ohost *Host = nil

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	_, xerr = ohost.ListInstalledFeatures(ctx)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, _, xerr := svc.CreateHost(ctx, abstract.HostRequest{
			ResourceName:   "MyHostTest",
			HostName:       "MyHostTest",
			ImageID:        "ImageID",
			PublicIP:       true,
			Single:         true,
			Subnets:        []*abstract.Subnet{},
			DefaultRouteIP: "127.0.0.1",
			DiskSize:       64,
			TemplateID:     "TemplateID",
		})
		require.Nil(t, xerr)

		host, xerr := LoadHost(ctx, svc, "MyHostTest")
		require.Nil(t, xerr)
		ohost := host.(*Host)

		list, xerr := ohost.ListInstalledFeatures(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, len(list), 0)

		xerr = host.Start(ctx)
		require.Nil(t, xerr)

		_, xerr = ohost.AddFeature(ctx, "ansible", data.Map{}, FeatureSettings{})
		require.Nil(t, xerr)

		svc._setLogLevel(2)
		list, xerr = ohost.ListInstalledFeatures(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, len(list), 1)
		require.EqualValues(t, list[0].GetName(), "ansible")

	})
	require.Nil(t, err)

}

func TestHost_InstalledFeatures(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ohost *Host = nil
	results, _ := ohost.InstalledFeatures(ctx)
	require.EqualValues(t, len(results), 0)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, _, xerr := svc.CreateHost(ctx, abstract.HostRequest{
			ResourceName:   "MyHostTest",
			HostName:       "MyHostTest",
			ImageID:        "ImageID",
			PublicIP:       true,
			Single:         true,
			Subnets:        []*abstract.Subnet{},
			DefaultRouteIP: "127.0.0.1",
			DiskSize:       64,
			TemplateID:     "TemplateID",
		})
		require.Nil(t, xerr)

		host, xerr := LoadHost(ctx, svc, "MyHostTest")
		require.Nil(t, xerr)
		ohost := host.(*Host)

		results, _ = ohost.InstalledFeatures(ctx)
		require.EqualValues(t, len(results), 0)

		xerr = host.Start(ctx)
		require.Nil(t, xerr)

		// Emulated SSH command response

		_, xerr = ohost.AddFeature(ctx, "ansible", data.Map{}, FeatureSettings{})
		require.Nil(t, xerr)

		results, _ = ohost.InstalledFeatures(ctx)
		require.EqualValues(t, len(results), 1)
		require.EqualValues(t, results[0], "ansible")

	})
	require.Nil(t, err)

}

func TestHost_IsFeatureInstalled(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ohost *Host = nil
	_, xerr = ohost.IsFeatureInstalled(ctx, "ansible")
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, _, xerr := svc.CreateHost(ctx, abstract.HostRequest{
			ResourceName:   "MyHostTest",
			HostName:       "MyHostTest",
			ImageID:        "ImageID",
			PublicIP:       true,
			Single:         true,
			Subnets:        []*abstract.Subnet{},
			DefaultRouteIP: "127.0.0.1",
			DiskSize:       64,
			TemplateID:     "TemplateID",
		})
		require.Nil(t, xerr)

		host, xerr := LoadHost(ctx, svc, "MyHostTest")
		require.Nil(t, xerr)
		ohost := host.(*Host)

		result, xerr := ohost.IsFeatureInstalled(ctx, "ansible")
		require.EqualValues(t, xerr, nil)
		require.EqualValues(t, result, false)

		xerr = host.Start(ctx)
		require.Nil(t, xerr)

		// Emulated SSH command response
		/*
			svc._updateOption("onsshcommand", func(in string) string {
				output := "echo \"\""
				switch in {
				case "/usr/bin/md5sum /opt/safescale/var/tmp/feature.ansible.check_pkg.sh":
					output = "echo \"b8bcb7fad595f7256fabf52be3c3cc73\""
				case "/usr/bin/md5sum /opt/safescale/var/tmp/feature.ansible.check_config.sh":
					output = "echo \"dc8990d0846a97ec65dcbc08b574a248\""
				}
				return output
			})
		*/

		_, xerr = ohost.AddFeature(ctx, "ansible", data.Map{}, FeatureSettings{})
		require.Nil(t, xerr)

		svc._setLogLevel(2)

		result, xerr = ohost.IsFeatureInstalled(ctx, "ansible")
		require.Nil(t, xerr)
		require.EqualValues(t, result, true)

	})
	require.Nil(t, err)

}
