package operations

import (
	"context"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/hashicorp/terraform-json"
)

type ResourcesRepository[T any] interface {
	Create(ctx context.Context, data T) error
	Read(ctx context.Context, id string) (*T, error)
	Update(ctx context.Context, id string, data T) error
	Delete(ctx context.Context, id string) error
}

type ResourcesRepositoryImpl[T any] struct {
	svc       iaas.Service
	lastState *tfjson.State
}

func (r ResourcesRepositoryImpl[T]) Create(ctx context.Context, data T) error {
	var err error
	// first, read terraform status
	r.lastState, err = r.svc.GetTerraformState(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (r ResourcesRepositoryImpl[T]) Read(ctx context.Context, id string) (*T, error) {

	//TODO implement me
	panic("implement me")
}

func (r ResourcesRepositoryImpl[T]) Update(ctx context.Context, id string, data T) error {
	//TODO implement me
	panic("implement me")
}

func (r ResourcesRepositoryImpl[T]) Delete(ctx context.Context, id string) error {
	//TODO implement me
	panic("implement me")
}
