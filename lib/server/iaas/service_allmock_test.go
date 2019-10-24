package iaas_test

import (
	servermocks "github.com/CS-SI/SafeScale/lib/server/iaas/mocks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers/aws"
	providermocks "github.com/CS-SI/SafeScale/lib/server/iaas/providers/mocks"
	"github.com/golang/mock/gomock"
	"testing"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
)

func TestServiceCreation(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	place := servermocks.NewMockLocation(mockCtrl)
	metaPlace := servermocks.NewMockLocation(mockCtrl)
	provider := providermocks.NewMockProvider(mockCtrl)

	metaPlace.EXPECT().CreateBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)
	metaPlace.EXPECT().FindBucket("0.safescale-8c5cf4ee2098b0e7104d80cecb25e302").Times(1)

	iaas.Register("aws", aws.New())
	serv, err := iaas.UseSpecialService("hell", provider, place, metaPlace)
	if err != nil {
		t.Fatal(err)
	}

	provider.EXPECT().ListRegions().Times(1).Return([]string{"east", "west"}, nil)

	regions, err := serv.ListRegions()
	if regions == nil {
		t.Fatal("nil regions")
	}
}
