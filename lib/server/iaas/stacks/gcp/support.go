package gcp

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// OpContext ...
type OpContext struct {
	Operation    *compute.Operation
	ProjectID    string
	Service      *compute.Service
	DesiredState string
}

// Result ...
type Result struct {
	State string
	Error error
	Done  bool
}

// RefreshResult ...
func RefreshResult(oco OpContext) (res Result, err error) {
	res = Result{}

	if oco.Operation != nil {
		if oco.Operation.Zone != "" { // nolint
			zoneURL, ierr := url.Parse(oco.Operation.Zone)
			if ierr != nil {
				return res, ierr
			}
			zone := getResourceNameFromSelfLink(*zoneURL)
			oco.Operation, err = oco.Service.ZoneOperations.Get(oco.ProjectID, zone, oco.Operation.Name).Do()
		} else if oco.Operation.Region != "" {
			regionURL, ierr := url.Parse(oco.Operation.Region)
			if ierr != nil {
				return res, ierr
			}
			region := getResourceNameFromSelfLink(*regionURL)
			oco.Operation, err = oco.Service.RegionOperations.Get(oco.ProjectID, region, oco.Operation.Name).Do()
		} else {
			oco.Operation, err = oco.Service.GlobalOperations.Get(oco.ProjectID, oco.Operation.Name).Do()
		}

		if oco.Operation == nil {
			if err == nil {
				return res, fmt.Errorf("no operation")
			}
			return res, err
		}

		res.State = oco.Operation.Status
		res.Error = err
		res.Done = res.State == oco.DesiredState

		return res, err
	}

	return res, scerr.NewError("no operation")
}

func waitUntilOperationIsSuccessfulOrTimeout(oco OpContext, poll time.Duration, duration time.Duration) (err error) {
	retryErr := retry.WhileUnsuccessful(func() error {
		r, anerr := RefreshResult(oco)
		if anerr != nil {
			return anerr
		}
		if !r.Done {
			return fmt.Errorf("not finished yet")
		}
		return nil
	}, poll, duration)

	return retryErr
}

// SelfLink ...
type SelfLink = url.URL

// IPInSubnet ...
type IPInSubnet struct {
	Subnet   SelfLink
	Name     string
	ID       string
	IP       string
	PublicIP string
}

func genURL(urlCand string) SelfLink {
	theURL, err := url.Parse(urlCand)
	if err != nil {
		return url.URL{}
	}
	return *theURL
}

func getResourceNameFromSelfLink(link SelfLink) string {
	stringRepr := link.String()
	parts := strings.Split(stringRepr, "/")
	return parts[len(parts)-1]
}

func indexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1 // not found.
}

func getRegionFromSelfLink(link SelfLink) (string, error) {
	stringRepr := link.String()
	if strings.Contains(stringRepr, "regions") {
		parts := strings.Split(stringRepr, "/")
		regionPos := indexOf("regions", parts)
		if regionPos != -1 {
			if (regionPos + 1) < len(parts) {
				return parts[regionPos+1], nil
			}
		}
		return "", fmt.Errorf("not a region link")
	}
	return "", scerr.InvalidRequestError("not a region link")
}

// func assertEq(exp, got interface{}) error {
// 	if !reflect.DeepEqual(exp, got) {
// 		return fmt.Errorf("wanted %v; Got %v", exp, got)
// 	}
// 	return nil
// }
