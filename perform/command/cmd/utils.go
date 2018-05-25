package cmd

import (
	pb "github.com/SafeScale/broker"
	utils "github.com/SafeScale/broker/utils"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

//getCurrentTenant returns the string of the current tenant set by broker
func getCurrentTenant() (string, error) {
	conn := utils.GetConnection()
	defer conn.Close()
	tenantSvc := pb.NewTenantServiceClient(conn)
	ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
	defer cancel()
	tenant, err := tenantSvc.Get(ctx, &google_protobuf.Empty{})
	if err != nil {
		return "", err
	}
	return tenant.String(), nil
}
