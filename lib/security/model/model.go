package model

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mssql"    //Import gorm mssql driver
	_ "github.com/jinzhu/gorm/dialects/mysql"    //Import gorm mysql driver
	_ "github.com/jinzhu/gorm/dialects/postgres" //Import gorm postgres driver
	_ "github.com/jinzhu/gorm/dialects/sqlite"   //Import gorm sqlite driver
	log "github.com/sirupsen/logrus"
)

//Service is a resource secured by the Gateway
type Service struct {
	ID      uint   `gorm:"primary_key; AUTO_INCREMENT"`
	Name    string `gorm:"unique_index"`
	BaseURL string
	Roles   []Role
}

//Role define a role relative to a service
type Role struct {
	ID                uint `gorm:"primary_key; AUTO_INCREMENT"`
	Name              string
	ServiceID         uint
	AccessPermissions []AccessPermission
	Users             []User `gorm:"many2many:user_roles;" `
}

//AccessPermission defines access pemission of a role towards a resource offered by a service
type AccessPermission struct {
	ID              uint   `gorm:"primary_key; AUTO_INCREMENT"`
	ResourcePattern string `gorm:"not nul"`
	Action          string `gorm:"not nul"`
	RoleID          uint
}

//User defines a user
type User struct {
	ID    uint   `gorm:"primary_key; AUTO_INCREMENT"`
	Email string `gorm:"unique_index"`
	Roles []Role `gorm:"many2many:user_roles;"`
}

//DataAccess wraps access to the database and implements utility requests
type DataAccess struct {
	dialect string
	dsn     string
}

//NewDataAccess creates a new DataAccess
func NewDataAccess(dialect, dsn string) *DataAccess {
	return &DataAccess{dialect: dialect, dsn: dsn}
}

//Get returns database access
func (da *DataAccess) Get() (*gorm.DB, error) {
	db, err := gorm.Open(da.dialect, da.dsn)
	if err != nil {
		return nil, err
	}
	return db, nil
}

//GetUserAccessPermissionsByService get user access permission by service
func (da *DataAccess) GetUserAccessPermissionsByService(email, serviceName string) (permissions []AccessPermission, err error) {
	db, err := da.Get()
	if err != nil {
		return permissions, err
	}
	defer func() {
		clErr := db.Close()
		if clErr != nil {
			log.Error(clErr)
		}
	}()
	var service Service
	if db.Where(&Service{Name: serviceName}).Take(&service).Error != nil {
		return permissions, err
	}
	var user User
	if db.Where(&User{Email: email}).Take(&user).Error != nil {
		return permissions, err
	}
	var roles []Role
	if db.Model(&user).Where(&Role{ServiceID: service.ID}).Preload("AccessPermissions").Related(&roles, "Roles").Error != nil {
		return permissions, err
	}

	for _, role := range roles {
		permissions = append(permissions, role.AccessPermissions...)
	}

	return permissions, err
}

//GetServiceByName get service by name
func (da *DataAccess) GetServiceByName(name string) (srv *Service, err error) {
	db, err := da.Get()
	if err != nil {
		return nil, err
	}
	defer func() {
		clErr := db.Close()
		if clErr != nil {
			log.Error(clErr)
		}
	}()

	if db.Where(&Service{Name: name}).Take(&srv).Error != nil {
		return nil, nil
	}
	return srv, nil
}

//Init initialize the database: drop tables if exists and create new empty ones
func (da *DataAccess) Init() (err error) {
	db, err := da.Get()
	if err != nil {
		return err
	}
	defer func() {
		clErr := db.Close()
		if clErr != nil {
			log.Error(clErr)
		}
	}()
	err = db.DropTableIfExists(&Service{}, &Role{}, &AccessPermission{}, &User{}).Error
	if err != nil {
		return err
	}
	err = db.AutoMigrate(&Service{}, &Role{}, &AccessPermission{}, &User{}).Error
	if err != nil {
		return err
	}
	return nil
}
