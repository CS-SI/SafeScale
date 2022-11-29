package iaas

import (
	"context"
	"reflect"
	"regexp"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

func Test_service_ListHostsWithTags(t *testing.T) {
	type fields struct {
		Provider             providers.Provider
		Location             objectstorage.Location
		tenantName           string
		cacheManager         *wrappedCache
		metadataBucket       abstract.ObjectStorageBucket
		metadataKey          *crypt.Key
		whitelistTemplateREs []*regexp.Regexp
		blacklistTemplateREs []*regexp.Regexp
		whitelistImageREs    []*regexp.Regexp
		blacklistImageREs    []*regexp.Regexp
	}
	type args struct {
		inctx   context.Context
		labels  []string
		details map[string]string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []*abstract.HostFull
		want1  fail.Error
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance := service{
				Provider:             tt.fields.Provider,
				Location:             tt.fields.Location,
				tenantName:           tt.fields.tenantName,
				cacheManager:         tt.fields.cacheManager,
				metadataBucket:       tt.fields.metadataBucket,
				metadataKey:          tt.fields.metadataKey,
				whitelistTemplateREs: tt.fields.whitelistTemplateREs,
				blacklistTemplateREs: tt.fields.blacklistTemplateREs,
				whitelistImageREs:    tt.fields.whitelistImageREs,
				blacklistImageREs:    tt.fields.blacklistImageREs,
			}
			got, got1 := instance.ListHostsWithTags(tt.args.inctx, tt.args.labels, tt.args.details)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ListHostsWithTags() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("ListHostsWithTags() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
