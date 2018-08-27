package model_test

import (
	"fmt"
	"testing"

	"github.com/CS-SI/SafeScale/security/model"
	"github.com/stretchr/testify/assert"
)

func Clean() {
	db := model.NewDataAccess("sqlite3", "/tmp/test.db").Get()
	defer db.Close()
	db.DropTableIfExists(&model.Service{}, &model.Role{}, &model.AccessPermission{}, &model.User{})
}

func TestModel(t *testing.T) {
	Clean()
	da := model.NewDataAccess("sqlite3", "/tmp/test.db")
	db := da.Get().Debug()
	defer db.Close()
	db.AutoMigrate(&model.Service{}, &model.Role{}, &model.AccessPermission{}, &model.User{})

	srv1 := model.Service{
		BaseURL: "http://srv1",
		Name:    "srv1",
	}
	assert.Nil(t, db.Create(&srv1).Error)
	usr1 := model.User{
		Email: "user@c-s.fr",
	}
	assert.Nil(t, db.Create(&usr1).Error)

	perm1 := model.AccessPermission{
		Action:          "GET",
		ResourcePattern: "*",
	}

	assert.Nil(t, db.Create(&perm1).Error)

	role1 := model.Role{
		Name: "USER",
	}

	assert.Nil(t, db.Create(&role1).Error)
	assert.Nil(t, db.Model(&role1).Association("AccessPermissions").Append(perm1).Error)
	assert.Nil(t, db.Model(&srv1).Association("Roles").Append(role1).Error)
	assert.Nil(t, db.Model(&usr1).Association("Roles").Append(role1).Error)
	assert.Equal(t, 1, db.Model(&usr1).Association("Roles").Count())
	assert.Equal(t, 1, db.Model(&srv1).Association("Roles").Count())
	assert.Equal(t, 1, db.Model(&role1).Association("AccessPermissions").Count())
	var roles []model.Role
	assert.Nil(t, db.Model(&usr1).Where(&model.Role{ServiceID: srv1.ID}).Preload("AccessPermissions").Related(&roles, "Roles").Error)
	assert.Equal(t, 1, len(roles))
	perms := da.GetUserAccessPermissionsByService("user@c-s.fr", "srv1")
	fmt.Println(perms)

}
