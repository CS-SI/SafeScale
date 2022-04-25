module github.com/CS-SI/SafeScale/v21

go 1.16

require (
	github.com/Masterminds/sprig/v3 v3.2.2
	github.com/antihax/optional v1.0.0
	github.com/aws/aws-sdk-go v1.43.45
	github.com/cpuguy83/go-md2man/v2 v2.0.1 // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/deckarep/golang-set v1.8.0
	github.com/denisbrodbeck/machineid v1.0.1
	github.com/dgraph-io/ristretto v0.1.0
	github.com/eko/gocache/v2 v2.2.0
	github.com/farmergreg/rfsnotify v0.0.0-20200716145600-b37be6e4177f
	github.com/felixge/fgprof v0.9.2
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0
	github.com/gofrs/uuid v4.2.0+incompatible
	github.com/gojuno/minimock/v3 v3.0.10
	github.com/golang/protobuf v1.5.2
	github.com/google/gofuzz v1.2.0
	github.com/gophercloud/gophercloud v0.24.0
	github.com/itchyny/gojq v0.12.7
	github.com/json-iterator/go v1.1.12
	github.com/magiconair/properties v1.8.6
	github.com/makholm/covertool v0.0.0-20210624102319-bb1c7c716204
	github.com/mitchellh/mapstructure v1.4.3
	github.com/nakabonne/gosivy v0.2.0
	github.com/oscarpicas/covertool v0.4.1
	github.com/oscarpicas/go-dsp v0.1.0
	github.com/oscarpicas/scribble v1.0.4
	github.com/oscarpicas/smetrics v0.1.0
	github.com/outscale/osc-sdk-go/osc v0.0.0-20200515123036-c82ce4912c6b
	github.com/ovh/go-ovh v1.1.0
	github.com/pelletier/go-toml/v2 v2.0.0-beta.8
	github.com/pkg/sftp v1.13.4
	github.com/sanity-io/litter v1.5.4
	github.com/sethvargo/go-password v0.2.0
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/viper v1.10.1
	github.com/stretchr/testify v1.7.1
	github.com/urfave/cli v1.22.5
	github.com/zserge/metric v0.1.0
	golang.org/x/crypto v0.0.0-20220131195533-30dcbda58838
	golang.org/x/exp v0.0.0-20210916165020-5cb4fee858ee
	golang.org/x/oauth2 v0.0.0-20220309155454-6242fa91716a
	golang.org/x/sys v0.0.0-20220328115105-d36c6a25d886
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
	gomodules.xyz/stow v0.2.4
	google.golang.org/api v0.74.0
	google.golang.org/grpc v1.45.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/fsnotify.v1 v1.4.7
)

replace gomodules.xyz/stow v0.2.4 => github.com/gomodules/stow v0.2.4

retract v21.0.0-20210521164327-48fde38a25be
