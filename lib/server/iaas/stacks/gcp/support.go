package gcp

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"google.golang.org/api/compute/v1"
	"net/url"
	"reflect"
	"strings"
	"time"
)

type OpContext struct {
	Operation *compute.Operation
	ProjectId string
	Service *compute.Service
	DesiredState string
}


type Result struct {
	State  string
	Error  error
	Done   bool
}

func RefreshResult(oco OpContext) (res Result, err error) {
	res = Result{}

	if oco.Operation != nil {
		if oco.Operation.Zone != "" {
			zoneUrl, _ := url.Parse(oco.Operation.Zone)
			zone := GetResourceNameFromSelfLink(*zoneUrl)
			oco.Operation, err = oco.Service.ZoneOperations.Get(oco.ProjectId, zone, oco.Operation.Name).Do()
		} else if oco.Operation.Region != "" {
			regionUrl, _ := url.Parse(oco.Operation.Region)
			region := GetResourceNameFromSelfLink(*regionUrl)
			oco.Operation, err = oco.Service.RegionOperations.Get(oco.ProjectId, region, oco.Operation.Name).Do()
		} else {
			oco.Operation, err = oco.Service.GlobalOperations.Get(oco.ProjectId, oco.Operation.Name).Do()
		}

		res.State = oco.Operation.Status
		res.Error = err
		res.Done = res.State == oco.DesiredState

		return res, err
	}

	return res, fmt.Errorf("no operation")
}

func waitUntilOperationIsSuccessfulOrTimeout(oco OpContext, poll time.Duration, duration time.Duration) (err error) {
	err = retry.WhileUnsuccessful(func() error {
		r, anerr := RefreshResult(oco)
		if anerr != nil {
			return anerr
		}
		if !r.Done {
			return fmt.Errorf("not finished yet")
		} else {
			return nil
		}
	}, poll, duration)

	return err
}

type SelfLink = url.URL

type IpInSubnet struct {
	Subnet SelfLink
	Name string
	ID string
	IP string
	PublicIP string
}


func genUrl(urlCand string) SelfLink {
	theUrl, err := url.Parse(urlCand)
	if err != nil {
		return url.URL{}
	}
	return *theUrl
}


func GetResourceNameFromSelfLink(link SelfLink) string {
	stringRepr := link.String()
	parts := strings.Split(stringRepr, "/")
	return parts[len(parts)-1]
}

func indexOf(element string, data []string) (int) {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1    //not found.
}

func GetRegionFromSelfLink(link SelfLink) (string, error) {
	stringRepr := link.String()
	if strings.Contains(stringRepr, "regions") {
		parts := strings.Split(stringRepr, "/")
		regionPos := indexOf("regions", parts)
		if regionPos != -1 {
			if (regionPos + 1) < len(parts) {
				return parts[regionPos + 1], nil
			}
		}
		return "", fmt.Errorf("Not a region link")
	} else {
		return "", fmt.Errorf("Not a region link")
	}
}

func assertEq(exp, got interface{}) error {
	if !reflect.DeepEqual(exp, got) {
		return fmt.Errorf("Wanted %v; Got %v", exp, got)
	}
	return nil
}