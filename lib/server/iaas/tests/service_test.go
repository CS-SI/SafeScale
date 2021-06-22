/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package tests

import (
	"encoding/json"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/mocks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/gojuno/minimock/v3"
	"github.com/sirupsen/logrus"
	"github.com/xrash/smetrics"

	_ "github.com/itchyny/gojq" // Not needed here, but we will need this later to do some serious testing
)

// this reads the file filename (generated by a 'safescale image list > filename'), and generates a list of abstract.Images for Jarowinkler
func getImages(filename string) ([]abstract.Image, error) {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	type Output struct {
		Result []abstract.Image
		Status string
	}

	var output Output
	err = json.Unmarshal(file, &output)
	if err != nil {
		return nil, err
	}
	return output.Result, nil
}

type Searcher func(iaas.Service, string) (*abstract.Image, fail.Error)

// just a copy of original code from iaas/service.go, but mockable (the 1st parameter of this function can be replaced by a mock),
// the only thing that changes is the method signature, the code inside is the same (even the commented/unused lines)
func SearchImageOriginal(svc iaas.Service, osname string) (*abstract.Image, fail.Error) {
	imgs, xerr := svc.ListImages(false)
	if xerr != nil {
		return nil, xerr
	}

	maxscore := 0.0
	maxi := -1
	// fields := strings.Split(strings.ToUpper(osname), " ")
	for i, img := range imgs {
		// score := 1 / float64(smetrics.WagnerFischer(strings.ToUpper(img.Name), strings.ToUpper(osname), 1, 1, 2))
		score := smetrics.JaroWinkler(strings.ToUpper(img.Name), strings.ToUpper(osname), 0.7, 5)
		// score := matchScore(fields, strings.ToUpper(img.Name))
		// score := SimilarityScore(osname, img.Name)
		if score > maxscore {
			maxscore = score
			maxi = i
		}
	}

	// fmt.Println(fields, len(fields))
	// fmt.Println(len(fields))
	if maxscore < 0.5 || maxi < 0 || len(imgs) == 0 {
		return nil, fail.NotFoundError("unable to find an image matching '%s'", osname)
	}

	logrus.Infof("Selected image: '%s' (ID='%s')", imgs[maxi].Name, imgs[maxi].ID)
	return &imgs[maxi], nil
}

func Test_service_SearchImage(t *testing.T) {
	// the file aws-west3-images.json has been created with:
	// safescale image list > aws-west3-images.json

	// this turns the json output into the list of images we would receive from the true AWS service
	// we don't actually use the network to run this test
	recovered, err := getImages("aws-west3-images.json")
	if err != nil {
		t.FailNow()
	}

	// we are mocking the output of the ListImages method -> so we are using ListImagesMock
	mc := minimock.NewController(t)
	common := mocks.NewServiceMock(mc)
	common.ListImagesMock.Expect(false).Return(recovered, nil)

	// now the tricky part, ideally we should use the code 'SearchImage' from the service, but we cannot
	// this is a code smell, it means that our code is really hard to test...
	// in order to do so, we created a new function, SearchImageOriginal, which is testable, this is, we can replace
	// true implementations by our mocks without touching anything else
	// the contents of our SearchImageOriginal are the same as in iaas/service.go:685
	res, err := SearchImageOriginal(common, "Ubuntu 18.04")
	if err != nil {
		t.FailNow()
	}

	// those are the true results of a request "Ubuntu 18.04" using AWS on west-3
	// now we can play tuning parameters in SearchImageOriginal and see what happens
	expected := &abstract.Image{
		ID:   "ami-00187db91863e8905",
		Name: "ubuntu-18.04-pke-201912101339",
	}

	if res.Name != expected.Name {
		t.Errorf("It seems that we selected %s, (expected %s)", res.Name, expected.Name)
		t.FailNow()
	}

	if res.ID != expected.ID {
		t.Errorf("It seems that we had the wrong ID %s, (expected %s)", res.ID, expected.ID)
		t.FailNow()
	}
}

func Test_service_SearchImage_AWS_Ubu20(t *testing.T) {
	// the file aws-west3-images.json has been created with:
	// safescale image list > aws-west3-images.json

	// this turns the json output into the list of images we would receive from the true AWS service
	// we don't actually use the network to run this test
	recovered, err := getImages("aws-west3-images.json")
	if err != nil {
		t.FailNow()
	}

	// we are mocking the output of the ListImages method -> so we are using ListImagesMock
	mc := minimock.NewController(t)
	common := mocks.NewServiceMock(mc)
	common.ListImagesMock.Expect(false).Return(recovered, nil)

	// now the tricky part, ideally we should use the code 'SearchImage' from the service, but we cannot
	// this is a code smell, it means that our code is really hard to test...
	// in order to do so, we created a new function, SearchImageOriginal, which is testable, this is, we can replace
	// true implementations by our mocks without touching anything else
	// the contents of our SearchImageOriginal are the same as in iaas/service.go:685
	res, err := SearchImageOriginal(common, "Ubuntu 20.04")
	if err != nil {
		t.FailNow()
	}

	expected := &abstract.Image{
		ID:   "ami-01af5da8f57705476",
		Name: "ubuntu-20.04-pke-1.17.5-202007101153",
	}

	// those are the true results of a request "Ubuntu 20.04" using AWS on west-3
	// now we can play tuning parameters in SearchImageOriginal and see what happens
	if res.Name != expected.Name {
		t.Errorf("It seems that we selected %s, (expected %s)", res.Name, expected.Name)
		t.FailNow()
	}

	if res.ID != expected.ID {
		t.Errorf("It seems that we had the wrong ID %s, (expected %s)", res.ID, expected.ID)
		t.FailNow()
	}
}

func Test_service_SearchImage_AWS_Centos7(t *testing.T) {
	// the file aws-west3-images.json has been created with:
	// safescale image list > aws-west3-images.json

	// this turns the json output into the list of images we would receive from the true AWS service
	// we don't actually use the network to run this test
	recovered, err := getImages("aws-west3-images.json")
	if err != nil {
		t.FailNow()
	}

	// we are mocking the output of the ListImages method -> so we are using ListImagesMock
	mc := minimock.NewController(t)
	common := mocks.NewServiceMock(mc)
	common.ListImagesMock.Expect(false).Return(recovered, nil)

	// now the tricky part, ideally we should use the code 'SearchImage' from the service, but we cannot
	// this is a code smell, it means that our code is really hard to test...
	// in order to do so, we created a new function, SearchImageOriginal, which is testable, this is, we can replace
	// true implementations by our mocks without touching anything else
	// the contents of our SearchImageOriginal are the same as in iaas/service.go:685
	res, err := SearchImageOriginal(common, "CentOS 7.4")
	if err != nil {
		t.FailNow()
	}

	// Notice here how Jarowinkler doesn't get right the major OS version number
	expected := &abstract.Image{
		ID:   "ami-0057f9b19b88b562c",
		Name: "CentOS 8.4.2105 x86_64",
	}

	// those are the true results of a request "CentOS 7.4" using AWS on west-3
	// now we can play tuning parameters in SearchImageOriginal and see what happens
	if res.Name != expected.Name {
		t.Errorf("It seems that we selected %s, (expected %s)", res.Name, expected.Name)
		t.FailNow()
	}

	if res.ID != expected.ID {
		t.Errorf("It seems that we had the wrong ID %s, (expected %s)", res.ID, expected.ID)
		t.FailNow()
	}
}

func Test_service_SearchImage_OVH_Centos7(t *testing.T) {
	recovered, err := getImages("ovh-images.json")
	if err != nil {
		t.FailNow()
	}

	mc := minimock.NewController(t)
	common := mocks.NewServiceMock(mc)
	common.ListImagesMock.Expect(false).Return(recovered, nil)

	res, err := SearchImageOriginal(common, "CentOS 7.4")
	if err != nil {
		t.FailNow()
	}

	expected := &abstract.Image{
		ID:   "1d848651-ab8c-43a8-9783-3bab62d6ddc1",
		Name: "Centos 7",
	}

	if res.Name != expected.Name {
		t.Errorf("It seems that we selected %s, (expected %s)", res.Name, expected.Name)
		t.FailNow()
	}

	if res.ID != expected.ID {
		t.Errorf("It seems that we had the wrong ID %s, (expected %s)", res.ID, expected.ID)
		t.FailNow()
	}
}

func Test_service_SearchImage_FE_Centos7(t *testing.T) {
	recovered, err := getImages("fe-images.json")
	if err != nil {
		t.FailNow()
	}

	mc := minimock.NewController(t)
	common := mocks.NewServiceMock(mc)
	common.ListImagesMock.Expect(false).Return(recovered, nil)

	res, err := SearchImageOriginal(common, "CentOS 7.4")
	if err != nil {
		t.FailNow()
	}

	expected := &abstract.Image{
		ID:   "df427f70-d88d-42fc-96b2-076b5ada293",
		Name: "CentOS8.2",
	}

	if res.Name != expected.Name {
		t.Errorf("It seems that we selected %s, (expected %s)", res.Name, expected.Name)
		t.FailNow()
	}

	if res.ID != expected.ID {
		t.Errorf("It seems that we had the wrong ID %s, (expected %s)", res.ID, expected.ID)
		t.FailNow()
	}
}

// TODO: Add your own tests
// Capture the outputs for other providers, put that into another json file and change the parameter of getImages accordingly
// In order to test other selection algorithms, just create another function like SearchImageOriginal with your own algo and
// use your function instead of SearchImageOriginal