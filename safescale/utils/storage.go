/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/serialize"
	"github.com/sethvargo/go-password/password"
)

func loadRsaPrivateKey(keyFilePath string) (*rsa.PrivateKey, error) {
	keyFilePath = utils.AbsPathify(keyFilePath)
	if _, err := os.Stat(keyFilePath); err != nil && os.IsNotExist(err) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("Failed to generate a 2048-bit RSA-key : %s", err.Error())
		}
		keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		file, err := os.Create(keyFilePath)
		if err != nil {
			return nil, fmt.Errorf("Failed to create the file '%s' : %s", keyFilePath, err.Error())
		}
		err = file.Chmod(0600)
		if err != nil {
			return nil, fmt.Errorf("Failed to set the access rights of file '%s' : %s", keyFilePath, err.Error())
		}
		_, err = file.Write(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("Failed to save the rsa key on file '%s' : %s", keyFilePath, err.Error())
		}
	} else if err != nil {
		return nil, fmt.Errorf("Failed to chek if file '%s' exists : %s", keyFilePath, err.Error())
	}
	file, err := os.Open(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to open '%s' : %s", keyFilePath, err.Error())
	}
	defer file.Close()
	fileStats, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("Failed to get file '%s' stats : %s", keyFilePath, err.Error())
	}
	fileSize := fileStats.Size()
	keyBytes := make([]byte, fileSize)
	_, err = file.Read(keyBytes)
	return x509.ParsePKCS1PrivateKey(keyBytes)
}

func hash(reader io.Reader) []byte {
	h := sha256.New()
	if _, err := io.Copy(h, reader); err != nil {
		log.Fatal(err)
	}
	return h.Sum(nil)
}

type BucketGenerator struct {
	buckets  []objectstorage.Bucket
	iterator int
	mutex    sync.Mutex
}

func NewBucketGenerator(buckets []objectstorage.Bucket) *BucketGenerator {
	return &BucketGenerator{
		buckets:  buckets,
		iterator: 0,
	}
}

func (bg *BucketGenerator) Next() objectstorage.Bucket {
	bg.mutex.Lock()
	iterator := bg.iterator
	bg.iterator = (bg.iterator + 1) % len(bg.buckets)
	bg.mutex.Unlock()
	return bg.buckets[iterator]
}

// Shard ...
type Shard struct {
	IsData     bool   `json:"isData,omitempty"`
	Position   int    `json:"position,omitempty"`
	Name       string `json:"name,omitempty"`
	BucketName string `json:"bucketName,omitempty"`
	CheckSum   []byte `json:"checkSum,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
}

// NewShard ...
func NewShard(reader io.Reader, position int, isData bool, bucket objectstorage.Bucket) Shard {
	var name string
	var err error

	for i := 0; ; i++ {
		if i > 10 {
			panic("Issue on random shard name generations (or extremly++ unlucky)  : %s")
		}
		name, err = password.Generate(64, 10, 10, false, false)
		if err != nil {
			panic(fmt.Sprintf("Failed to generate shard name : %s", err.Error()))
		}
		name += ".bin"
		if obj, err := bucket.GetObject(name); err != nil && obj == nil {
			break
		}
	}
	shard := Shard{
		IsData:     isData,
		Position:   position,
		Name:       name,
		BucketName: bucket.GetName(),
		CheckSum:   hash(reader),
	}
	return shard
}

// GetNonce ...
func (s *Shard) GetNonce(nonceSize int) ([]byte, error) {
	if s.Nonce == nil {
		s.Nonce = make([]byte, nonceSize)
		if _, err := io.ReadFull(rand.Reader, s.Nonce); err != nil {
			return nil, fmt.Errorf("Failed to read rand.Reader : %s", err)
		}
	}
	return s.Nonce, nil
}

// GetStorageInfos ...
func (s *Shard) GetStorageInfos() (string, string, error) {
	if s.Name == "" {
		return "", "", fmt.Errorf("Shard name is not set")
	}
	if s.BucketName == "" {
		return "", "", fmt.Errorf("bucketname is not set")
	}
	return s.Name, s.BucketName, nil
}

// ToString ...
func (s *Shard) ToString() string {
	if s == nil {
		return "nil"
	}
	return fmt.Sprintf("Shard : \n isData   : %t\n position : %d\n name     : %s\n bucket   : %s\n nonce    : %x\n checkSum : %x", s.IsData, s.Position, s.Name, s.BucketName, s.Nonce, s.CheckSum)
}

//ChunkGroup ...
type ChunkGroup struct {
	FileName    string `json:"filename,omitempty"`
	FileSize    int64  `json:"filsize,omitempty"`
	Date        string `json:"date,omitempty"`
	AesPassword string `json:"aespassword,omitempty"`

	Shards         []*Shard `json:"shards,omitempty"`
	NbDataShards   int      `json:"nbDataShards,omitempty"`
	NbParityShards int      `json:"nbParityShards,omitempty"`
	PaddingSize    int64    `json:"paddingSize,omitempty"`

	BucketNames []string `json:"bucketNames,omitempty"`
}

// NewChunkGroup ...
func NewChunkGroup(fileName string, fileSize int64, bucketNames []string) (*ChunkGroup, error) {
	password, err := password.Generate(64, 10, 10, false, false)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate the AES password : %s", err.Error())
	}
	date := time.Now()
	cg := ChunkGroup{
		AesPassword: password,
		FileName:    fileName,
		FileSize:    fileSize,
		Date:        date.Format(time.UnixDate),
		BucketNames: bucketNames,
	}

	return &cg, nil
}

//InitShards ...
func (cg *ChunkGroup) InitShards(chunkSize int, parityRatio float32) (int, int, error) {
	cg.NbDataShards = int(math.Ceil(float64(cg.FileSize) / float64(chunkSize)))
	cg.NbParityShards = int(math.Ceil(float64(cg.NbDataShards) / float64(parityRatio)))
	if cg.NbDataShards > 256 {
		return 0, 0, fmt.Errorf("Too many datashards, you have to increase the chunk size to at least %d bytes", cg.FileSize/256+1)
	}
	cg.Shards = make([]*Shard, cg.NbDataShards+cg.NbParityShards)
	cg.PaddingSize = int64(chunkSize) - (cg.FileSize % int64(chunkSize))

	return cg.NbDataShards, cg.NbParityShards, nil
}

//RegisterShards ...
func (cg *ChunkGroup) RegisterShards(dataReaders []io.Reader, parityReaders []io.Reader, bucketGenerator *BucketGenerator) {
	firstDataNil := 0
	firstParityNil := 0
	for ; cg.Shards[firstDataNil] != nil; firstDataNil++ {
	}
	for ; cg.Shards[cg.NbDataShards+firstParityNil] != nil; firstParityNil++ {
	}

	for i := 0; i < len(dataReaders); i++ {
		shard := NewShard(dataReaders[i], firstDataNil+i, true, bucketGenerator.Next())
		cg.Shards[firstDataNil+i] = &shard
	}
	for i := 0; i < len(parityReaders); i++ {
		shard := NewShard(parityReaders[i], firstParityNil+i, false, bucketGenerator.Next())
		cg.Shards[cg.NbDataShards+firstParityNil+i] = &shard
	}
}

// GetGCM ...
func (cg *ChunkGroup) GetGCM() (cipher.AEAD, error) {
	hash := sha256.Sum256([]byte(cg.AesPassword))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, fmt.Errorf("Failed to get a new cipher : %s", err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Failed to get a new GCM : %s", err.Error())
	}
	return gcm, nil
}

//GetNonce ...
func (cg *ChunkGroup) GetNonce(shardNum int, nonceSize int) ([]byte, error) {
	if shardNum >= len(cg.Shards) {
		return nil, fmt.Errorf("there is only %d dataShards", len(cg.Shards))
	}
	return cg.Shards[shardNum].GetNonce(nonceSize)
}

//GetStorageInfo ...
func (cg *ChunkGroup) GetStorageInfo(shardNum int) (string, string, error) {
	if shardNum >= len(cg.Shards) {
		return "", "", fmt.Errorf("there is only %d dataShards", len(cg.Shards))
	}
	return cg.Shards[shardNum].GetStorageInfos()
}

//GetStorageInfos ...
func (cg *ChunkGroup) GetStorageInfos() ([]string, []string, error) {
	var err error
	shardNames := make([]string, len(cg.Shards))
	shardBucketName := make([]string, len(cg.Shards))
	for i := range cg.Shards {
		shardNames[i], shardBucketName[i], err = cg.Shards[i].GetStorageInfos()
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to get all shards info : %s", err.Error())
		}
	}
	return shardNames, shardBucketName, nil
}

// GetBucketNames ...
func (cg *ChunkGroup) GetBucketNames() []string {
	return cg.BucketNames
}

// GetFileInfos ...
func (cg *ChunkGroup) GetFileInfos() (string, string, int64) {
	return cg.FileName, cg.Date, cg.FileSize
}

//ToString ...
func (cg *ChunkGroup) ToString() string {
	str := fmt.Sprintf("ChunkGroup : \n fileName       : %s\n date           :%s\n fileSize       : %d\n aesPassword    : %s\n buckets        : \n", cg.FileName, cg.Date, cg.FileSize, cg.AesPassword)
	for _, name := range cg.BucketNames {
		str += fmt.Sprintf(" --->%s\n", name)
	}
	str += fmt.Sprintf(" nbDataShards   : %d\n nbParityShards : %d\n", cg.NbDataShards, cg.NbParityShards)
	for _, shard := range cg.Shards {
		str += shard.ToString()
		str += "\n"
	}
	return str
}

//Encrypt ....
func (cg *ChunkGroup) Encrypt() ([]byte, *KeyInfo, error) {
	cgJSON, err := serialize.ToJSON(cg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize chunkGroup : %s", err.Error())
	}
	keyInfo, err := NewKeyInfo()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate KeyInfo : %s", err.Error())
	}
	gcm, err := keyInfo.GetGCM()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get GCM : %s", err.Error())
	}
	cgEncrypted := gcm.Seal(nil, keyInfo.Nonce, cgJSON, nil)

	return cgEncrypted, keyInfo, nil
}

//DecryptChunkGroup
func DecryptChunkGroup(encrypted []byte, ki *KeyInfo) (*ChunkGroup, error) {
	gcm, err := ki.GetGCM()
	if err != nil {
		return nil, fmt.Errorf("Failed to get GCM : %s", err.Error())
	}
	cgJSON, err := gcm.Open(nil, ki.GetNonce(), encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt chunkGroup : %s", err.Error())
	}
	var cg ChunkGroup
	err = serialize.FromJSON(cgJSON, &cg)
	if err != nil {
		return nil, fmt.Errorf("failed to unserialize the chunkGroup from JSON : %s", err.Error())
	}
	return &cg, nil
}

//Key Info ...
type KeyInfo struct {
	AesPassword string `json:"aespassword,omitempty"`
	Nonce       []byte `json:"nonce,omitempty"`
}

// NewKeyInfo ...
func NewKeyInfo() (*KeyInfo, error) {
	password, err := password.Generate(64, 10, 10, false, false)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate the AES password : %s", err.Error())
	}
	ki := KeyInfo{
		AesPassword: password,
	}

	return &ki, nil
}

// GetGCM ...
func (ki *KeyInfo) GetGCM() (cipher.AEAD, error) {
	hash := sha256.Sum256([]byte(ki.AesPassword))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, fmt.Errorf("Failed to get a new cipher : %s", err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Failed to get a new GCM : %s", err.Error())
	}
	if ki.Nonce == nil {
		ki.Nonce = make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, ki.Nonce); err != nil {
			return nil, fmt.Errorf("Failed to read rand.Reader : %s", err)
		}
	}
	return gcm, nil
}

//GetNonce ...
func (ki *KeyInfo) GetNonce() []byte {
	return ki.Nonce
}

func (ki *KeyInfo) Encrypt(keyFile string) ([]byte, error) {
	kiJSON, err := serialize.ToJSON(ki)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize keyInfo : %s", err.Error())
	}
	rsaKey, err := loadRsaPrivateKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load the rsa key : %s", err.Error())
	}
	encryptedKI, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaKey.PublicKey, kiJSON, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt the keyInfo : %s", err.Error())
	}
	return encryptedKI, nil
}

func DecryptKeyInfo(encrypted []byte, keyFile string) (*KeyInfo, error) {
	rsaKey, err := loadRsaPrivateKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load the rsa key : %s", err.Error())
	}
	kiJSON, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt the keyInfo : %s", err.Error())
	}
	var ki KeyInfo
	err = serialize.FromJSON(kiJSON, &ki)
	if err != nil {
		return nil, fmt.Errorf("failed to unserialize the keyInfo from JSON : %s", err.Error())
	}
	return &ki, nil
}
