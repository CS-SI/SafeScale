//go:build (integration && featuretests) || allintegration
// +build integration,featuretests allintegration

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

package remotedesktop

import (
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/stretchr/testify/require"
)

func RemoteDesktop(t *testing.T) {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	nb := r.Intn(100)
	name := "rdtest" + strconv.Itoa(nb)

	out, err := helpers.GetOutput(fmt.Sprintf("safescale cluster create --complexity=Normal --cidr '192.168.38.0/24' --flavor=BOH --os 'Ubuntu 20.04' %s", name))
	require.Nil(t, err)

	defer func() {
		_, err := helpers.GetOutput(fmt.Sprintf("safescale cluster delete -y %s", name))
		require.Nil(t, err)
	}()

	var res string
	res, err = helpers.RunJq(out, ".status")
	require.Nil(t, err)
	require.Equal(t, "success", res)

	username := "foo"
	password := "bar"

	out, err = helpers.GetOutput(fmt.Sprintf("safescale cluster feature add -p Username=%s -p Password=%s %s remotedesktop", username, password, name))
	require.Nil(t, err)

	res, err = helpers.RunJq(out, ".status")
	require.Nil(t, err)
	require.Equal(t, "success", res)

	out, _ = helpers.GetOutput(fmt.Sprintf("safescale cluster inspect %s", name))

	fmt.Println("OUT : ", out)

	url, err := helpers.RunJq(out, fmt.Sprintf(".result.remote_desktop.\"%s-master-1\"", name))

	if err != nil {
		fmt.Println("Error : ", err)
	}

	fmt.Println("URL : ", url)

	browser := rod.New().MustConnect()

	defer browser.MustClose()

	browser.IgnoreCertErrors(true)

	page := browser.MustPage(url).MustWaitIdle()

	time.Sleep(5 * time.Second)

	page.MustWaitIdle().MustElements("input").First().MustInput("bar")
	page.MustElements("input")[1].MustInput("bar").MustType(input.Enter)

	fmt.Println("found : ", page.MustElements("input").First())
	fmt.Println("found : ", page.MustElements("input")[1])

	divs := len(page.MustElements("div"))

	if divs != 17 {
		t.Fatal("Wrong number of divs : ", divs)
	}

}

func RemoteDesktopUbuntu18(t *testing.T) {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	nb := r.Intn(100)
	name := "rdu18test" + strconv.Itoa(nb)

	out, err := helpers.GetOutput(fmt.Sprintf("safescale cluster create --complexity=Normal --cidr '192.168.39.0/24' --flavor=BOH --os 'Ubuntu 18.04' %s", name))
	require.Nil(t, err)

	defer func() {
		_, err := helpers.GetOutput(fmt.Sprintf("safescale cluster delete -y %s", name))
		require.Nil(t, err)
	}()

	var res string
	res, err = helpers.RunJq(out, ".status")
	require.Nil(t, err)
	require.Equal(t, "success", res)

	username := "foo"
	password := "bar"

	out, err = helpers.GetOutput(fmt.Sprintf("safescale cluster feature add -p Username=%s -p Password=%s %s remotedesktop", username, password, name))
	require.Nil(t, err)

	res, err = helpers.RunJq(out, ".status")
	require.Nil(t, err)
	require.Equal(t, "success", res)

	out, _ = helpers.GetOutput(fmt.Sprintf("safescale cluster inspect %s", name))

	fmt.Println("OUT : ", out)

	url, err := helpers.RunJq(out, fmt.Sprintf(".result.remote_desktop.\"%s-master-1\"", name))

	if err != nil {
		fmt.Println("Error : ", err)
	}

	fmt.Println("URL : ", url)

	browser := rod.New().MustConnect()

	defer browser.MustClose()

	browser.IgnoreCertErrors(true)

	page := browser.MustPage(url).MustWaitIdle()

	time.Sleep(5 * time.Second)

	page.MustWaitIdle().MustElements("input").First().MustInput("bar")
	page.MustElements("input")[1].MustInput("bar").MustType(input.Enter)

	fmt.Println("found : ", page.MustElements("input").First())
	fmt.Println("found : ", page.MustElements("input")[1])

	divs := len(page.MustElements("div"))

	if divs != 17 {
		t.Fatal("Wrong number of divs : ", divs)
	}

}

func RemoteDesktopUbuntu22(t *testing.T) {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	nb := r.Intn(100)
	name := "rdu22test" + strconv.Itoa(nb)

	out, err := helpers.GetOutput(fmt.Sprintf("safescale cluster create --complexity=Normal --cidr '192.168.40.0/24' --flavor=BOH --os 'Ubuntu 22.04' %s", name))
	if err != nil {
		fmt.Println(err)
	}
	require.Nil(t, err)

	defer func() {
		_, err := helpers.GetOutput(fmt.Sprintf("safescale cluster delete -y %s", name))
		require.Nil(t, err)
	}()

	var res string
	res, err = helpers.RunJq(out, ".status")
	require.Nil(t, err)
	require.Equal(t, "success", res)

	username := "foo"
	password := "bar"

	out, err = helpers.GetOutput(fmt.Sprintf("safescale cluster feature add -p Username=%s -p Password=%s %s remotedesktop", username, password, name))
	if err != nil {
		fmt.Println(err)
	}
	require.Nil(t, err)

	res, err = helpers.RunJq(out, ".status")
	require.Nil(t, err)
	require.Equal(t, "success", res)

	out, _ = helpers.GetOutput(fmt.Sprintf("safescale cluster inspect %s", name))

	fmt.Println("OUT : ", out)

	url, err := helpers.RunJq(out, fmt.Sprintf(".result.remote_desktop.\"%s-master-1\"", name))

	if err != nil {
		fmt.Println("Error : ", err)
	}

	fmt.Println("URL : ", url)

	browser := rod.New().MustConnect()

	defer browser.MustClose()

	browser.IgnoreCertErrors(true)

	page := browser.MustPage(url).MustWaitIdle()

	time.Sleep(5 * time.Second)

	page.MustWaitIdle().MustElements("input").First().MustInput("bar")
	page.MustElements("input")[1].MustInput("bar").MustType(input.Enter)

	fmt.Println("found : ", page.MustElements("input").First())
	fmt.Println("found : ", page.MustElements("input")[1])

	divs := len(page.MustElements("div"))

	if divs != 17 {
		t.Fatal("Wrong number of divs : ", divs)
	}

}

func RemoteDesktopCentos7(t *testing.T) {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	nb := r.Intn(100)
	name := "rdc7test" + strconv.Itoa(nb)

	out, err := helpers.GetOutput(fmt.Sprintf("safescale cluster create --complexity=Normal --cidr '192.168.41.0/24' --flavor=BOH --os 'CentOS 7' %s", name))
	if err != nil {
		fmt.Println(err)
	}
	require.Nil(t, err)

	defer func() {
		_, err := helpers.GetOutput(fmt.Sprintf("safescale cluster delete -y %s", name))
		require.Nil(t, err)
	}()

	var res string
	res, err = helpers.RunJq(out, ".status")
	require.Nil(t, err)
	require.Equal(t, "success", res)

	username := "foo"
	password := "bar"

	out, err = helpers.GetOutput(fmt.Sprintf("safescale cluster feature add -p Username=%s -p Password=%s %s remotedesktop", username, password, name))
	if err != nil {
		fmt.Println(err)
	}
	require.Nil(t, err)

	res, err = helpers.RunJq(out, ".status")
	require.Nil(t, err)
	require.Equal(t, "success", res)

	out, _ = helpers.GetOutput(fmt.Sprintf("safescale cluster inspect %s", name))

	fmt.Println("OUT : ", out)

	url, err := helpers.RunJq(out, fmt.Sprintf(".result.remote_desktop.\"%s-master-1\"", name))

	if err != nil {
		fmt.Println("Error : ", err)
	}

	fmt.Println("URL : ", url)

	browser := rod.New().MustConnect()

	defer browser.MustClose()

	browser.IgnoreCertErrors(true)

	page := browser.MustPage(url).MustWaitIdle()

	time.Sleep(5 * time.Second)

	page.MustWaitIdle().MustElements("input").First().MustInput("bar")
	page.MustElements("input")[1].MustInput("bar").MustType(input.Enter)

	fmt.Println("found : ", page.MustElements("input").First())
	fmt.Println("found : ", page.MustElements("input")[1])

	divs := len(page.MustElements("div"))

	if divs != 17 {
		t.Fatal("Wrong number of divs : ", divs)
	}

}

func RemoteDesktopFailedUserAlreadyexists(t *testing.T) {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	nb := r.Intn(100)
	name := "rdusertest" + strconv.Itoa(nb)

	out, err := helpers.GetOutput(fmt.Sprintf("safescale cluster create --complexity=Normal --cidr '192.168.42.0/24' --flavor=BOH --os 'Ubuntu 20.04' %s", name))
	require.Nil(t, err)

	defer func() {
		_, err := helpers.GetOutput(fmt.Sprintf("safescale cluster delete -y %s", name))
		require.Nil(t, err)
	}()

	var res string
	res, err = helpers.RunJq(out, ".status")
	require.Nil(t, err)
	require.Equal(t, "success", res)

	username := "safescale"
	password := "bar"

	out, err = helpers.GetOutput(fmt.Sprintf("safescale cluster feature add -p Username=%s -p Password=%s %s remotedesktop", username, password, name))
	require.NotNil(t, err, "Should have failed because user already exists")

}

func RemoteDesktopCladm(t *testing.T) {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	nb := r.Intn(100)
	name := "rdcladmtest" + strconv.Itoa(nb)

	out, err := helpers.GetOutput(fmt.Sprintf("safescale cluster create --complexity=Normal --cidr '192.168.43.0/24' --flavor=BOH --os 'Ubuntu 20.04' %s", name))
	if err != nil {
		fmt.Println(err)
	}
	require.Nil(t, err)

	defer func() {
		_, err := helpers.GetOutput(fmt.Sprintf("safescale cluster delete -y %s", name))
		require.Nil(t, err)
	}()

	var res string
	res, err = helpers.RunJq(out, ".status")
	require.Nil(t, err)
	require.Equal(t, "success", res)

	username := "cladm"
	password, _ := helpers.RunJq(out, ".result.admin_password")

	out, err = helpers.GetOutput(fmt.Sprintf("safescale cluster feature add -p Username=%s -p Password=\"%s\" %s remotedesktop", username, password, name))
	if err != nil {
		fmt.Println(err)
	}
	require.Nil(t, err)

	res, err = helpers.RunJq(out, ".status")
	require.Nil(t, err)
	require.Equal(t, "success", res)

	out, _ = helpers.GetOutput(fmt.Sprintf("safescale cluster inspect %s", name))

	fmt.Println("OUT : ", out)

	url, err := helpers.RunJq(out, fmt.Sprintf(".result.remote_desktop.\"%s-master-1\"", name))

	if err != nil {
		fmt.Println("Error : ", err)
	}

	fmt.Println("URL : ", url)

	browser := rod.New().MustConnect()

	defer browser.MustClose()

	browser.IgnoreCertErrors(true)

	page := browser.MustPage(url).MustWaitIdle()

	time.Sleep(5 * time.Second)

	page.MustWaitIdle().MustElements("input").First().MustInput("bar")
	page.MustElements("input")[1].MustInput("bar").MustType(input.Enter)

	fmt.Println("found : ", page.MustElements("input").First())
	fmt.Println("found : ", page.MustElements("input")[1])

	divs := len(page.MustElements("div"))

	if divs != 17 {
		t.Fatal("Wrong number of divs : ", divs)
	}
}

func init() {

}
