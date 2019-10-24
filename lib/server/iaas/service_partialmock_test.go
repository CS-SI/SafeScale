package iaas_test

import (
	"fmt"
	servermocks "github.com/CS-SI/SafeScale/lib/server/iaas/mocks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers/aws"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/davecgh/go-spew/spew"
	"github.com/golang/mock/gomock"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
)

func TestServiceCreationWithAws(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	_, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestServiceListRegions(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	regions, err := serv.ListRegions()
	if err != nil {
		t.Fatal(err)
	}
	if len(regions) == 0 {
		t.Fatal("No regions detected")
	}

	withUsWest := false
	for _, v := range regions {
		if strings.Contains(v, "us-west-2") {
			withUsWest = true
		}
	}

	if !withUsWest {
		t.Fatal(fmt.Errorf("failure retrieving regions: Us West region not detected"))
	}
}

func TestServiceListImages(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	_, err = serv.ListImages(true)
	if err != nil {
		t.Fatal(err)
	}
}

func TestServiceListTemplates(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	_, err = serv.ListTemplates(true)
	if err != nil {
		t.Fatal(err)
	}
}

func TestServiceCreateNetwork(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	_, err = serv.CreateNetwork(resources.NetworkRequest{
		Name:       "TestNet",
		IPVersion:  0,
		CIDR:       "192.168.0.12/24",
		DNSServers: []string{"1.1.1.1"},
	})
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			t.Fatal(awerr.Code())
		} else {
			t.Fatalf("something else: %v", err)
		}

	}
}

func TestServiceGetNetwork(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	_, err = serv.GetNetwork("vpc-82ad31c2")
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			t.Fatal(awerr.Code())
		} else {
			t.Fatalf("something else: %v", err)
		}

	}
}

func TestServiceGetNetworkByName(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	_, err = serv.GetNetworkByName("xxx")
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			t.Fatal(awerr.Code())
		} else {
			t.Fatalf("something else: %v", err)
		}

	}
}

func TestServiceListNetwork(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	resList, err := serv.ListNetworks()
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			t.Fatal(awerr.Code())
		} else {
			t.Fatalf("something else: %v", err)
		}

	}

	for _, res := range resList {
		fmt.Print(spew.Sdump(res))
	}

}

func TestServiceDeleteNetwork(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	err = serv.DeleteNetwork("TestNet")
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			t.Fatal(awerr.Code())
		} else {
			t.Fatalf("something else: %v", err)
		}

	}
}

func TestServiceListZones(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	regs, err := serv.ListAvailabilityZones()
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			t.Fatal(awerr.Code())
		} else {
			t.Fatalf("something else: %v", err)
		}
	}

	withUsWest := false
	for k := range regs {
		if strings.Contains(k, "us-west-2a") {
			withUsWest = true
		}
	}

	if !withUsWest {
		t.Fatal(fmt.Errorf("failure retrieving zones: Us West zone not detected"))
	}
}

func TestServiceCreateVolume(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	_, err = serv.CreateVolume(resources.VolumeRequest{
		Name: "Whateva",
		Size: 3,
	})
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			t.Fatal(awerr.Code())
		}
	}
}

func TestServiceListVolume(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	vols, err := serv.ListVolumes()
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			t.Fatal(awerr.Code())
		} else {
			t.Fatalf("something else: %v", err)
		}
	}
	for _, vol := range vols {
		fmt.Println(spew.Sdump(vol))
	}
}

func TestDeleteVolume(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	err = serv.DeleteVolume("Whateva")
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if !ok {
			t.Fatal(awerr.Code())
		} else {
			t.Fatalf("something else: %v", err)
		}
	}

	vorr, err := serv.CreateVolume(resources.VolumeRequest{
		Name: "Drama",
		Size: 7,
	})
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			t.Fatal(awerr.Code())
		} else {
			t.Fatalf("something else: %v", err)
		}
	}

	if vorr.Size != 7 {
		t.Fatal(fmt.Errorf("failure in Volume size"))
	}

	err = serv.DeleteVolume(vorr.ID)
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			t.Fatal(awerr.Code())
		} else {
			t.Fatalf("something else: %v", err)
		}
	}
}

// FIXME Add volume attachment tests...
func TestServiceCreateVolumeAttachment(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	_, err = serv.CreateVolumeAttachment(resources.VolumeAttachmentRequest{
		Name:     "WhatevaVol",
		HostID:   "hoi",
		VolumeID: "Vid",
	})
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			if awerr.Code() != "InvalidVolume.NotFound" {
				t.Fatal(awerr.Code())
			}
		} else {
			t.Fatalf("something else: %v", err)
		}
	}

	volid := ""
	hostid := ""

	davols, err := serv.ListVolumes()
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			t.Fatal(awerr.Code())
		} else {
			t.Fatalf("something else: %v", err)
		}
	}
	for _, avol := range davols {
		fmt.Print(spew.Sdump(avol))
		volid = avol.ID
		if volid != "" {
			break
		}
	}

	dahosts, err := serv.ListHosts()
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			t.Fatal(awerr.Code())
		} else {
			t.Fatalf("something else: %v", err)
		}
	}
	for _, host := range dahosts {
		fmt.Print(spew.Sdump(host))
		hostid = host.ID
		if hostid != "" {
			break
		}
	}
	if len(dahosts) == 0 {
		t.Fatal("no fake hosts available")
	}

	_, err = serv.CreateVolumeAttachment(resources.VolumeAttachmentRequest{
		Name:     "WhatevaVol",
		HostID:   hostid,
		VolumeID: volid,
	})
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			if awerr.Code() != "InvalidVolume.NotFound" {
				t.Fatal(awerr.Code())
			}
		} else {
			t.Fatalf("something else: %v", err)
		}
	}
}

// FIXME Add volume attachment tests...
func TestServiceListInstances(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	dahosts, err := serv.ListHosts()
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			t.Fatal(awerr.Code())
		} else {
			t.Fatalf("something else: %v", err)
		}
	}
	for _, host := range dahosts {
		fmt.Print(spew.Sdump(host))
	}
	if len(dahosts) == 0 {
		t.Fatal("no fake hosts available")
	}
}

func TestServiceCreateHost(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", nil, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = serv.CreateHost(resources.HostRequest{
		ResourceName:   "sauron",
		HostName:       "sauron",
		Networks:       nil,
		DefaultGateway: nil,
		PublicIP:       false,
		TemplateID:     "fuchsia",
		ImageID:        "nonono",
		KeyPair:        nil,
		Password:       "fdfasf",
		DiskSize:       32,
	})
	if err != nil {
		awerr, ok := err.(awserr.Error)
		if ok {
			t.Fatal(awerr.Code())
		} else {
			t.Fatalf("something else: %v", err)
		}
	}

}
