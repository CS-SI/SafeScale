package object

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/graymeta/stow"
	// necessary for connect
	_ "github.com/graymeta/stow/s3"
	_ "github.com/graymeta/stow/swift"
)

//ReadTenant ReadTenant
func (client *Location) ReadTenant(projectName string, provider string) (Config, error) {
	log.Println("Connect: ", provider)
	var conf Config
	var filename string

	if provider == "Flexibleengine" {
		filename = "/home/pierre//go/src/github.com/pcrume/tests/flexibleEngine.toml"
	}
	if provider == "OVH" {
		filename = "/home/pierre/.safescale/ovh.toml"
	}
	if provider == "CLOUDWat" {
		filename = "/home/pierre//go/src/github.com/pcrume/tests/CloudWatt.toml"
	}

	_, err := toml.DecodeFile(filename, &conf)
	if err != nil {
		log.Println("erreur", filename, err)
		return conf, err
	}

	return conf, err
}

//Connect Connect
func (client *Location) Connect(conf Config) (err error) {
	//	log.Println("Connection stow: ", conf)
	var kind string
	//var conf Config
	var config stow.ConfigMap

	config = stow.ConfigMap{
		"access_key_id":   conf.Key,
		"secret_key":      conf.Secretkey,
		"username":        conf.User,
		"key":             conf.Key,
		"endpoint":        conf.Endpoint,
		"tenant_name":     conf.Tenant,
		"tenant_auth_url": conf.Auth,
		"region":          conf.Region,
		"domain":          conf.Domain,
		"kind":            conf.Types,
	}
	kind = conf.Types

	// Check config location
	err = stow.Validate(kind, config)
	if err != nil {
		log.Println("erreur Validate", err)
		return err
	}
	client.Location.Location, err = stow.Dial(kind, config)
	if err != nil {
		log.Println("erreur Dial", err, client.Location.Location)
		return err
	}
	return err
}

// ItemSize ItemSize
func (client *Location) ItemSize(ContainerName string, item string) (sizeIt int64, err error) {
	itemstow, err := client.GetItem(ContainerName, item)
	if err != nil {
		log.Println("erreur ItemSize : ", ContainerName, '.', item, err)
		return sizeIt, err
	}
	sizeIt, err = stow.Item.Size(itemstow)
	if err != nil {
		log.Println("erreur size item : ", ContainerName, '.', item, err)
		return sizeIt, err
	}
	return sizeIt, err
}

// ItemEtag ItemEtag
func (client *Location) ItemEtag(ContainerName string, item string) (ETag string, err error) {
	itemstow, err := client.GetItem(ContainerName, item)
	if err != nil {
		log.Println("erreur ItemEtag : ", ContainerName, '.', item, err)
		return ETag, err
	}
	ETag, err = stow.Item.ETag(itemstow)
	if err != nil {
		log.Println("erreur Etag item : ", ContainerName, '.', item, err)
		return ETag, err
	}
	return ETag, err
}

// ItemLastMod ItemLastMod
func (client *Location) ItemLastMod(ContainerName string, item string) (tim time.Time, err error) {
	itemstow, err := client.GetItem(ContainerName, item)
	if err != nil {
		log.Println("erreur ItemLastMod : ", ContainerName, '.', item, err)
		return tim, err
	}
	tim, err = stow.Item.LastMod(itemstow)
	if err != nil {
		log.Println("erreur LastModTime item : ", ContainerName, '.', item, err)
		return tim, err
	}
	return tim, err
}

// ItemID ItemID
func (client *Location) ItemID(ContainerName string, item string) (id string, err error) {
	itemstow, err := client.GetItem(ContainerName, item)
	if err != nil {
		log.Println("erreur ItemID : ", ContainerName, '.', item, err)
		return id, err
	}
	id = stow.Item.ID(itemstow)
	return id, err
}

// ItemMetadata ItemMetadata
func (client *Location) ItemMetadata(ContainerName string, item string) (meta map[string]interface{}, err error) {
	itemstow, err := client.GetItem(ContainerName, item)
	if err != nil {
		log.Println("erreur ItemMetadata : ", ContainerName, '.', item, err)
		return meta, err
	}
	meta, err = stow.Item.Metadata(itemstow)
	if err != nil {
		log.Println("erreur MetadataItem item : ", ContainerName, '.', item, err)
		return meta, err
	}
	return meta, err
}

//GetItem GetItem
func (client *Location) GetItem(ContainerName string, item string) (myItem stow.Item, err error) {
	c1, err := client.Location.Location.Container(ContainerName)
	if err != nil {
		log.Println("erreur location.Container : ", ContainerName, err)
		return myItem, err
	}
	myItem, err = stow.Container.Item(c1, item)
	return myItem, err
}

//Remove Remove
func (client *Location) Remove(ContainerName string) (err error) {
	log.Println("Stow Remove Container => ", ContainerName)
	err = client.Location.Location.RemoveContainer(ContainerName)
	if err != nil {
		log.Println("erreur Remove Container : ", ContainerName, err)
		return err
	}
	return err
}

//Create Create
func (client *Location) Create(ContainerName string) (err error) {
	log.Println("Stow Create Container => ", ContainerName)
	_, err = client.Location.Location.CreateContainer(ContainerName)
	if err != nil {
		log.Println("erreur CreateContainer : ", ContainerName, err)
		return err
	}
	return err
}

//SearchPatternForMapUser SearchPatternForMapUser
func SearchPatternForMapUser(key string, pattern string, m map[string]interface{}) bool {
	find := false
	for k := range m {
		str := fmt.Sprintf("%v", m[k])
		matched, err := filepath.Match(pattern, str)
		if matched == true && key == k {
			find = true
		}
		if err != nil {
			log.Println("err", err)
			find = false
		}
	}
	return find
}

// Inspect Liste List All Containers And Items
func (client *Location) Inspect() (s map[string][]string, err error) {
	log.Println(" Inspect  ")
	var oneItemFund = false
	//vsf := make([]string, 0)
	vsf := make(map[string][]string)
	//log.Println("WalkContainers")
	err = stow.WalkContainers(client.Location.Location, stow.NoPrefix, 100,
		func(c stow.Container, err error) error {
			if err != nil {
				return err
			}
			//log.Println("Nom du Container  => : ", c.Name())
			/***/
			err = stow.Walk(c, stow.NoPrefix, 100,
				func(item stow.Item, err error) error {
					if err != nil {
						return err
					}
					//log.Println("  Item => : ", item.Name())
					oneItemFund = true
					//vsf = append(vsf, c.Name())
					//vsf = append(vsf, item.Name())
					vsf[c.Name()] = append(vsf[c.Name()], item.Name())

					return nil
				})
			if oneItemFund == false {
				//log.Println("No Item found corresponding to filter")
				vsf[c.Name()] = append(vsf[c.Name()], "")
			}

			return nil
		})
	if err != nil {
		log.Println("Inspect => : ", err)
	}
	return vsf, err
}

// SumSize SumSize
func (client *Location) SumSize() (size string) {
	var err error
	log.Println(" SumSize  ")
	var vSize int64
	var oneItemFund = false
	err = stow.WalkContainers(client.Location.Location, stow.NoPrefix, 100,
		func(c stow.Container, err error) error {
			if err != nil {
				return err
			}
			//log.Println("Nom du Container  => : ", c.Name())
			/***/
			err = stow.Walk(c, stow.NoPrefix, 100,
				func(item stow.Item, err error) error {
					if err != nil {
						return err
					}
					//log.Println("  Item => : ", item.Name())
					oneItemFund = true

					sizeItem, err := item.Size()
					if err != nil {
						return err
					}
					vSize = vSize + sizeItem
					return nil
				})
			if oneItemFund == false {
				//log.Println("No Item found corresponding to filter")
			}

			return nil
		})
	if err != nil {
		log.Println(" SumSize => : ", err)
	}
	return byteSize(uint64(vSize))
}

const (
	cBYTE = 1.0 << (10 * iota)
	cKILOBYTE
	cMEGABYTE
	cGIGABYTE
	cTERABYTE
)

func byteSize(bytes uint64) string {
	unit := ""
	value := float32(bytes)

	switch {
	case bytes >= cTERABYTE:
		unit = "T"
		value = value / cTERABYTE
	case bytes >= cGIGABYTE:
		unit = "G"
		value = value / cGIGABYTE
	case bytes >= cMEGABYTE:
		unit = "M"
		value = value / cMEGABYTE
	case bytes >= cKILOBYTE:
		unit = "K"
		value = value / cKILOBYTE
	case bytes >= cBYTE:
		unit = "B"
	case bytes == 0:
		return "0"
	}

	stringValue := fmt.Sprintf("%.1f", value)
	stringValue = strings.TrimSuffix(stringValue, ".0")
	return fmt.Sprintf("%s%s", stringValue, unit)
}

// Count Liste List All Containers And Items serch ALL => key = "*" or key =""
func (client *Location) Count(key string, pattern string) (count int, err error) {
	log.Println("Count  ")
	var oneItemFund = false
	var trouve bool
	count = 0
	err = stow.WalkContainers(client.Location.Location, stow.NoPrefix, 100,
		func(c stow.Container, err error) error {
			if err != nil {
				return err
			}
			err = stow.Walk(c, stow.NoPrefix, 100,
				func(item stow.Item, err error) error {
					if err != nil {
						return err
					}
					if key == "*" || key == "" {
						trouve = true
					} else {
						meta := make(map[string]interface{})
						meta, err = stow.Item.Metadata(item)
						trouve = SearchPatternForMapUser(key, pattern, meta)
					}
					if trouve == true {
						count = count + 1
					}
					return nil
				})
			if oneItemFund == false {
			}
			return nil
		})
	if err != nil {
		log.Println("Container WalkContainers => : ", err)
	}
	return count, err
}

// FilterByMetadata Liste List All Containers And Items byPattern
func (client *Location) FilterByMetadata(key string, pattern string) (s map[string][]string, err error) {
	log.Println("FilterByMetadata => key : ", key, " pattern : ", pattern)
	var oneItemFund = false
	//vsf := make([]string, 0)
	vsf := make(map[string][]string)
	//log.Println("WalkContainers")
	err = stow.WalkContainers(client.Location.Location, stow.NoPrefix, 100,
		func(c stow.Container, err error) error {
			if err != nil {
				return err
			}

			err = stow.Walk(c, stow.NoPrefix, 100,
				func(item stow.Item, err error) error {
					if err != nil {
						return err
					}
					meta := make(map[string]interface{})
					meta, err = stow.Item.Metadata(item)
					trouve := SearchPatternForMapUser(key, pattern, meta)
					if trouve == true {
						//log.Println("  Item => : ", item.Name(), " Metadata Item => ", meta)
						oneItemFund = true
						//vsf = append(vsf, c.Name())
						//vsf = append(vsf, item.Name())
						vsf[c.Name()] = append(vsf[c.Name()], item.Name())
					}
					return nil
				})
			if oneItemFund == false {
			}

			return nil
		})
	if err != nil {
		log.Println("Container WalkContainers => : ", err)
	}
	return vsf, err
}

// ListContainers ListContainers
func (client *Location) ListContainers() (s []string, err error) {
	log.Println("Stow ListContainers Region ", client.Region)
	log.Println("Stow ListContainers TenantName ", client.TenantName)
	vsf := make([]string, 0)
	err = stow.WalkContainers(client.Location.Location, stow.NoPrefix, 100,
		func(c stow.Container, err error) error {
			if err != nil {
				return err
			}

			vsf = append(vsf, c.Name())
			return nil
		})
	if err != nil {
		log.Println("Container WalkContainers => : ", err)
	}
	return vsf, err
}

// FilterItemsByMetadata  FilterItemsByMetadata
func (client *Location) FilterItemsByMetadata(ContainerName string, key string, pattern string) (s map[string][]string, err error) {
	var oneItemFund = false
	//vsf := make([]string, 0)
	vsf := make(map[string][]string)
	c, err := client.Location.Location.Container(ContainerName)
	if err != nil {
		log.Println("Location.Container => : ", ContainerName, err)
		return vsf, err
	}

	err = stow.Walk(c, stow.NoPrefix, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			meta := make(map[string]interface{})
			meta, err = stow.Item.Metadata(item)
			trouve := SearchPatternForMapUser(key, pattern, meta)
			if trouve == true {
				//log.Println("  Item => : ", item.Name(), " Metadata Item => ", meta)
				oneItemFund = true
				//vsf = append(vsf, c.Name())
				//vsf = append(vsf, item.Name())
				vsf[c.Name()] = append(vsf[c.Name()], item.Name())
			}
			return nil
		})
	if oneItemFund == false {
		log.Println("No Item found corresponding to filter", key, pattern)
	}
	return vsf, err
}

// ListItems  ListItems
func (client *Location) ListItems(ContainerName string) (s map[string][]string, err error) {
	//vsf := make([]string, 0)
	vsf := make(map[string][]string)
	c, err := client.Location.Location.Container(ContainerName)
	if err != nil {
		log.Println("Location.Container => : ", ContainerName, err)
		return vsf, err
	}
	//log.Println("Location.Container => : ", c.Name())
	err = stow.Walk(c, stow.NoPrefix, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			//log.Println("  Item => : ", item.Name())
			//vsf = append(vsf, c.Name())
			//vsf = append(vsf, item.Name())
			vsf[c.Name()] = append(vsf[c.Name()], item.Name())
			return nil
		})
	return vsf, err
}

// Clear  Clear
func (client *Location) Clear(myContainerName string) (err error) {
	log.Println("Clear => ContainerName : ", myContainerName)
	c1, err := client.Location.Location.Container(myContainerName)
	if err != nil {
		log.Println("Location.Container => : ", myContainerName, err)
		return err
	}
	err = stow.Walk(c1, stow.NoPrefix, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			log.Println("RemoveItem => : ", item.Name(), " for Container ", c1.Name())
			err = stow.Container.RemoveItem(c1, item.Name())
			if err != nil {
				log.Println("erreur RemoveItem => : ", err)
				return err
			}
			client.NbItem = 0
			return err
		})
	return err
}

// ExtractItem ExtractItem
func (client *Location) ExtractItem(container string, itemName string, f *os.File, pseekTo *int64, plength *int64) (err error) {

	var seekTo int64
	var length int64
	defer f.Close()
	c1, err1 := client.Location.Location.Container(container)
	if err1 != nil {
		log.Println("erreur location.Container container : ", container, err1)
		return err1
	}
	myItem, err := stow.Container.Item(c1, itemName)
	if err != nil {
		return err
	}
	sizeIt, err := stow.Item.Size(myItem)
	if err != nil {
		return err
	}

	if pseekTo == nil {
		seekTo = 0
	} else {
		seekTo = *pseekTo
	}

	if plength == nil {
		length = sizeIt
	} else {
		length = *plength
	}
	log.Printf("ExtractItem   %s.%s extracted until %d bytes to %d bytes to %s ", container, itemName, seekTo, length, f.Name())
	err = stow.Walk(c1, stow.NoPrefix, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			//log.Println(item.Name())
			if item.Name() == itemName {
				r, err := item.Open()
				if err != nil {
					log.Println(r, err)
					return err
				}
				defer r.Close()

				if seekTo == 0 && length >= sizeIt {
					nbytes, err := io.CopyN(f, r, sizeIt)
					if err != nil {
						log.Println(r, err)
						return err
					}
					f.Sync()
					log.Println("Extract Item By BytesRange => ", container, item.Name(), " wrote ", nbytes, " to ", f.Name())
				} else {

					buf := make([]byte, seekTo)

					if _, err := io.ReadAtLeast(r, buf, int(seekTo)); err != nil {
						log.Fatal(err)
					}

					bufbis := make([]byte, length)
					if _, err := io.ReadAtLeast(r, bufbis, int(length)); err != nil {
						log.Println("error ")
						log.Fatal(err)
					}

					rbis := bytes.NewReader(bufbis)
					nbytes, err := io.CopyBuffer(f, rbis, bufbis)
					if err != nil {
						log.Println(r, err)
						return err
					}
					f.Sync()
					log.Println("Extract Item By BytesRange => ", container, item.Name(), " wrote ", nbytes, " to ", f.Name())
				}
			}
			return nil
		})
	return err
}

// ExtractItemContent ExtractItemContent
func (client *Location) ExtractItemContent(container string, itemName string) (content []byte, err error) {

	c1, err1 := client.Location.Location.Container(container)
	if err1 != nil {
		log.Println("erreur location.Container : ", container, err1)
		return content, err1
	}
	myItem, err := stow.Container.Item(c1, itemName)
	if err != nil {
		return content, err
	}

	err = stow.Walk(c1, stow.NoPrefix, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			//log.Println(item.Name())
			if item.Name() == itemName {
				r, err := item.Open()
				if err != nil {
					log.Println(r, err)
					return err
				}
				defer r.Close()
				sizeIt, err := stow.Item.Size(myItem)
				if err != nil {
					log.Println("erreur size item : ", container, '.', itemName, err)
					return err
				}

				content = make([]byte, sizeIt)
				io.ReadFull(r, content)
				log.Println("ExtractItemContent => ", container, ".", myItem.Name(), " wrote to ", string(content[:]))
			}
			return nil
		})
	if err != nil {
		log.Println("ExtractItemContent => : ", err)
	}
	return content, err
}

// PutItem PutItem
func (client *Location) PutItem(container string, itemName string, f *os.File, metadata map[string]interface{}) (err error) {

	log.Println("PutItem => ", container, ".", itemName, " from ", f.Name())
	c1, err1 := client.Location.Location.Container(container)
	if err1 != nil {
		log.Println("erreur location.Container Container : ", container, err1)
		return err1
	}

	fileName := f.Name()
	fi, e := os.Stat(fileName)
	if e != nil {
		return e
	}
	// get the size
	size := fi.Size()
	defer f.Close()
	//b, err := ioutil.ReadAll(uploadFile)
	//log.Println(b)
	if err != nil {
		log.Println("erreur read file on PutItem  ", container, ".", itemName, " from ", fileName)
	}
	r := bufio.NewReader(f)
	_, err = stow.Container.Put(c1, itemName, r, size, metadata)
	if err != nil {
		log.Println("erreur stow.Container.Put ", itemName, err)
		return nil
	}
	client.NbItem = client.NbItem + 1

	return err
}

// PutItemContent PutItemContent
func (client *Location) PutItemContent(container string, itemName string, content []byte, metadata map[string]interface{}) (err error) {

	log.Println("PutItemContent => ", container, ".", itemName, " from ", string(content[:]))
	c1, err1 := client.Location.Location.Container(container)
	if err1 != nil {
		log.Println("erreur location.Container : ", container, err1)
		return err1
	}
	r := bytes.NewReader(content)
	size := int64(len(content))
	_, err = stow.Container.Put(c1, itemName, r, size, metadata)
	if err != nil {
		log.Println("erreur stow.Container.Put ", itemName, err)
		return nil
	}
	client.NbItem = client.NbItem + 1
	return err
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:len(buf)])
	}
	return chunks
}

//BytesBufferToItem BytesBufferToItem
func BytesBufferToItem(i int, location stow.Location, container string, bufferedReader io.Reader, byteSlice []byte, itemName string, size int, numBytesRead int, metadata map[string]interface{}) (err error) {
	p := make([]byte, numBytesRead)
	c1, err1 := location.Container(container)
	if err1 != nil {
		log.Println("erreur location.Container : ", container, err1)
		return err1
	}
	n, err := bufferedReader.Read(p)
	if err == io.EOF {
		return err
	}
	r := bytes.NewReader(p)
	//log.Println("buffer ", string(p[:n]))
	itemNamePart := itemName + strconv.Itoa(i)
	metadata["Split"] = itemName
	item, err := stow.Container.Put(c1, itemNamePart, r, int64(n), metadata)
	if err != nil {
		log.Printf("Put Item : %s split %d bytes:  erreur %s \n", item.Name(), numBytesRead, err)
		return err
	}
	log.Printf("Put Item : %s split %d bytes \n", item.Name(), numBytesRead)
	return err
}

// PutItemByChunk PutItemByChunk
func (client *Location) PutItemByChunk(container string, itemName string, chunkSize int, f *os.File, metadata map[string]interface{}) (err error) {
	log.Printf("PutItemByChunk => multi part  %s.%s* from %s spliting by %d bytes parts", container, itemName, f.Name(), chunkSize)
	c1, err1 := client.Location.Location.Container(container)
	if err1 != nil {
		log.Println("erreur location.Container : ", container, err1)
		return err1
	}

	fileName := f.Name()
	fi, e := os.Stat(fileName)
	if e != nil {
		log.Println(e)
		return e
	}
	// get the size
	size := fi.Size()
	defer f.Close()
	if err != nil {
		// reading file failed, handle appropriately
		log.Println("erreur read file on PutItem  ", container, ".", itemName, " from ", fileName)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bufferedReader := bufio.NewReader(f)
	p := make([]byte, chunkSize)
	var i int
	restbBytes := int(size)
	for {
		if restbBytes < chunkSize {
			chunkSize = restbBytes
		}
		err = BytesBufferToItem(i, client.Location.Location, c1.Name(), bufferedReader, p, itemName, int(size), chunkSize, metadata)
		restbBytes = restbBytes - chunkSize
		client.NbItem = client.NbItem + 1
		if restbBytes == 0 {
			break
		}
		i++
	}
	return err
}

func writeBuffToFile(byteSlice []byte, fileName string) (err error) {
	f, err := os.Create(fileName)
	if err != nil {
		log.Println("erreur !!!!!! ", f, err)
		return err
	}
	bufferedWriter := bufio.NewWriter(f)
	bytesWritten, err := bufferedWriter.Write(byteSlice)
	if err != nil {
		log.Printf("erreur %s when Bytes written: %d for filename  %s \n", err, bytesWritten, fileName)
	}
	bufferedWriter.Flush()
	f.Close()
	return err
}

//WaitAllPutITemTerminated WaitAllPutITemTerminated
func (client *Location) WaitAllPutITemTerminated(key string, pattern string) (err error) {
	log.Println("WaitAllPutITemTerminated : ", key, pattern)
	count, err := client.Count(key, pattern)
	if err != nil {
		return err
	}
	fmt.Println("deb WaitAllPutITemTerminated  :", count)
	fmt.Println("deb WaitAllPutITemTerminated  :", client.NbItem)
	for count != client.NbItem {
		count, err = client.Count(key, pattern)
		if err != nil {
			fmt.Println(err)
			break
		}
		time.Sleep(1 * time.Second)
		fmt.Println("boucle sleep count  WaitAllPutITemTerminated  :", count)
		fmt.Println("boucle sleep NbItem WaitAllPutITemTerminated  :", client.NbItem)
		if count == client.NbItem {
			break
		}
		fmt.Println("count WaitAllPutITemTerminated  :", count)
		fmt.Println("NbItem WaitAllPutITemTerminated  :", client.NbItem)
	}
	return err
}
