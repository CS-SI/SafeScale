package object

import (
	"os"
	"time"

	"github.com/graymeta/stow"
)

//ObjectStorageAPI ObjectStorageAPI
type ObjectStorageAPI interface {
	ReadTenant(projectName string, provider string) (Config, error)
	Connect(conf Config) error
	Inspect() (map[string][]string, error)
	SumSize() string
	Count(key string, pattern string) (int, error)
	WaitAllPutITemTerminated(key string, valuePattern string) error
	FilterByMetadata(key string, valuePattern string) (map[string][]string, error)

	ListContainers() ([]string, error)

	ListItems(ContainerName string) (map[string][]string, error)
	FilterItemsByMetadata(ContainerName string, key string, pattern string) (map[string][]string, error)

	Create(ContainerName string) error
	Remove(ContainerName string) error
	Clear(myContainerName string) error

	PutItemByChunk(container string, itemName string, chunksize int, f *os.File, metadata map[string]interface{}) error
	PutItem(container string, itemName string, f *os.File, metadata map[string]interface{}) error
	PutItemContent(container string, itemName string, content []byte, metadata map[string]interface{}) error

	ExtractItem(container string, itemName string, f *os.File, pseekTo *int64, plength *int64) error
	ExtractItemContent(container string, itemName string) ([]byte, error)

	ItemSize(ContainerName string, item string) (int64, error)
	ItemEtag(ContainerName string, item string) (string, error)
	ItemLastMod(ContainerName string, item string) (time.Time, error)
	ItemID(ContainerName string, item string) (id string)
	ItemMetadata(ContainerName string, item string) (map[string]interface{}, error)
}

//Location Location
type Location struct {
	Location         StowLocation
	NbItem           int
	IdentityEndpoint string
	TenantName       string
	Password         string
	Username         string
	Region           string
}

//StowLocation StowLocation
type StowLocation struct {
	Location stow.Location
}

//Config Config
type Config struct {
	Types        string
	Envauth      bool
	Authversion  int
	Auth         string
	Endpointtype string
	Tenantdomain string
	Tenant       string
	Domain       string
	User         string
	Key          string
	Region       string
	Secretkey    string
	Endpoint     string
}
