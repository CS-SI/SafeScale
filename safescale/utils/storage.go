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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/serialize"
	"github.com/sethvargo/go-password/password"
	log "github.com/sirupsen/logrus"
)

//
//
//
//------------------- MISC -----------------------------------------------------------------------------------------------------------

//Generate a random AES password
func generateAesPassword(withSymbols bool) (string, error) {
	password, err := password.Generate(64, 10, map[bool]int{true: 10, false: 0}[withSymbols], false, true)
	if err != nil {
		return "", fmt.Errorf("Failed to generate the AES password : %s", err.Error())
	}
	return password, nil
}

//Load the RSA-2048 key stored into the file given in parameters (stored with x509.MarshalPKCS1PrivateKey)
//If the file did not exists he will be created and a random RSA-2048 key will be stored in it
func loadRsaPrivateKey(keyFilePath string) (*rsa.PrivateKey, error) {
	var file *os.File

	keyFilePath = utils.AbsPathify(keyFilePath)
	if _, err := os.Stat(keyFilePath); err != nil && os.IsNotExist(err) {
		file, err := os.Create(keyFilePath)
		if err != nil {
			return nil, fmt.Errorf("Failed to create the file '%s' : %s", keyFilePath, err.Error())
		}
		err = file.Chmod(0600)
		if err != nil {
			return nil, fmt.Errorf("Failed to set the access rights of file '%s' : %s", keyFilePath, err.Error())
		}

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("Failed to generate a 2048-bit RSA-key : %s", err.Error())
		}
		_, err = file.Write(x509.MarshalPKCS1PrivateKey(privateKey))
		if err != nil {
			return nil, fmt.Errorf("Failed to save the rsa key on file '%s' : %s", keyFilePath, err.Error())
		}
	} else if err != nil {
		return nil, fmt.Errorf("Failed to chek if file '%s' exists : %s", keyFilePath, err.Error())
	} else {
		file, err = os.Open(keyFilePath)
		if err != nil {
			return nil, fmt.Errorf("Failed to open '%s' : %s", keyFilePath, err.Error())
		}
	}

	var keyBytes bytes.Buffer
	_, err := keyBytes.ReadFrom(file)
	if err != nil {
		return nil, fmt.Errorf("Failed to read the keyFile : %s", err.Error())
	}
	err = file.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to close the keyFile : %s", err.Error())
	}
	return x509.ParsePKCS1PrivateKey(keyBytes.Bytes())
}

// Hash will compute and return a SHA-256 hash of the datas of the reader
func Hash(reader io.Reader) string {
	h := sha256.New()
	if _, err := io.Copy(h, reader); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

//
//
//
//------------------- BucketGenerator ------------------------------------------------------------------------------------------------

// BucketGenerator ...
type BucketGenerator struct {
	buckets  []objectstorage.Bucket
	iterator int
	mutex    sync.Mutex
}

// NewBucketGenerator return a bucketGenerator returning the buckets given as parameters
func NewBucketGenerator(buckets []objectstorage.Bucket) *BucketGenerator {
	return &BucketGenerator{
		buckets:  buckets,
		iterator: 0,
	}
}

//Next return the bucket currently pointed by the iterator and then iterate
func (bg *BucketGenerator) Next() objectstorage.Bucket {
	bg.mutex.Lock()
	iterator := bg.iterator
	bg.iterator = (bg.iterator + 1) % len(bg.buckets)
	bg.mutex.Unlock()
	return bg.buckets[iterator]
}

//
//
//
//------------------- Shard ----------------------------------------------------------------------------------------------------------

// Shard ...
type Shard struct {
	//The name the shard have in the object storage
	Name string `json:"name,omitempty"`
	//The name of the bucket where the shard is stored
	BucketName string `json:"bucketName,omitempty"`
	//The shard checkSum (after encryption)
	CheckSum string `json:"checkSum,omitempty"`
	//The Nonce used to encrypt the shard
	Nonce []byte `json:"nonce,omitempty"`
}

// NewShard return a new Shard
func NewShard(bucket objectstorage.Bucket) *Shard {
	var name string
	var err error

	for i := 0; ; i++ {
		if i > 10 {
			panic(fmt.Sprintf("Issue on random shard name generations (or extremly++ unlucky)  : %v", err))
		}
		// To be accepted by a maximum of objects storages, passwords should be generated without symbols
		if name, err = generateAesPassword(false); err != nil {
			continue
		}
		name += ".bin"
		//TODO-AJ is it usefull, as it could take up to 25 sec to check all the shards? (+- 0.10 sec / shard with 100ms ping)
		if obj, err := bucket.GetObject(name); err != nil && obj == nil {
			break
		}
	}
	shard := Shard{
		Name:       name,
		BucketName: bucket.GetName(),
	}
	return &shard
}

// GetStorageInfo return the name and bucket name of the shard
func (s *Shard) GetStorageInfo() (string, string) {
	return s.Name, s.BucketName
}

// GetCheckSum ...
func (s *Shard) GetCheckSum() string {
	return s.CheckSum
}

// GetNonce return the nonce
func (s *Shard) GetNonce() []byte {
	return s.Nonce
}

//GenerateNonce generate, set and return a nonce of the required size
func (s *Shard) GenerateNonce(nonceSize int) ([]byte, error) {
	s.Nonce = make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, s.Nonce); err != nil {
		return nil, fmt.Errorf("Failed to read rand.Reader : %s", err)
	}
	return s.Nonce, nil
}

//SetCheckSum will hash the file in the reader and store the result as a string
func (s *Shard) SetCheckSum(reader io.Reader) string {
	s.CheckSum = Hash(reader)
	return s.CheckSum
}

// ToString return a string representation on a shard ready to be displayed
func (s *Shard) ToString() string {
	if s == nil {
		return "nil"
	}
	return fmt.Sprintf("Shard : \n name     : %s\n bucket   : %s\n nonce    : %x\n checkSum : %x", s.Name, s.BucketName, s.Nonce, s.CheckSum)
}

//
//
//
//------------------- ChunkGroup -----------------------------------------------------------------------------------------------------

//ChunkGroup ...
type ChunkGroup struct {
	FileName    string `json:"filename,omitempty"`
	FileSize    int64  `json:"filsize,omitempty"`
	Date        string `json:"date,omitempty"`
	AesPassword string `json:"aespassword,omitempty"`

	Shards                 []*Shard `json:"shards,omitempty"`
	NbDataShards           int      `json:"nbdatashards,omitempty"`
	NbParityShards         int      `json:"nbparityshards,omitempty"`
	ChunkSize              int      `json:"chunksize,omitempty"`
	NbDataShardsPerBatch   int      `json:"nbdatachunkperbatch,omitempty"`
	NbParityShardsPerBatch int      `json:"nbparitychunkperbatch,omitempty"`
	PaddingSize            int      `json:"paddingsize,omitempty"`

	BucketNames []string `json:"bucketnames,omitempty"`
}

// NewChunkGroup return a chunk group initialized with a new random aesPassword, buckets, and file infos
func NewChunkGroup(fileName string, fileSize int64, bucketNames []string) (*ChunkGroup, error) {
	password, err := generateAesPassword(true)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate the AES password : %s", err.Error())
	}

	cg := ChunkGroup{
		FileName:    fileName,
		FileSize:    fileSize,
		Date:        time.Now().Format(time.UnixDate),
		AesPassword: password,
		BucketNames: bucketNames,
	}

	return &cg, nil
}

// GetFileInfos return the file name, upload date and size
func (cg *ChunkGroup) GetFileInfos() (string, string, int64) {
	return cg.FileName, cg.Date, cg.FileSize
}

// GetNbShards return the number of data shards and parity shards
func (cg *ChunkGroup) GetNbShards() (int, int) {
	return cg.NbDataShards, cg.NbParityShards
}

// GetBatchSizeInfo return the chunkSize, the number of data shards and parity shards per batch
func (cg *ChunkGroup) GetBatchSizeInfo() (int, int, int) {
	return cg.ChunkSize, cg.NbDataShardsPerBatch, cg.NbParityShardsPerBatch
}

// GetPaddingSize return the padding size of the last data shard
func (cg *ChunkGroup) GetPaddingSize() int {
	return cg.PaddingSize
}

// GetBucketNames return the list of bucket names
func (cg *ChunkGroup) GetBucketNames() []string {
	return cg.BucketNames
}

//GetNonce return the nonce of a given shard
func (cg *ChunkGroup) GetNonce(shardNum int) []byte {
	if shardNum >= len(cg.Shards) {
		return nil
	}
	return cg.Shards[shardNum].GetNonce()
}

//GetStorageInfo return the storageInfos of a given shard (fileName, bucketName)
func (cg *ChunkGroup) GetStorageInfo(shardNum int) (string, string) {
	if shardNum >= len(cg.Shards) {
		return "", ""
	}
	return cg.Shards[shardNum].GetStorageInfo()
}

//GetCheckSum return the checkSum of a given shard
func (cg *ChunkGroup) GetCheckSum(shardNum int) string {
	if shardNum >= len(cg.Shards) {
		return ""
	}
	return cg.Shards[shardNum].GetCheckSum()
}

// GetEncryptedChunkSize return the size of an encrypted chunk
func (cg *ChunkGroup) GetEncryptedChunkSize() int {
	return (cg.ChunkSize/16 + 1) * 16
}

// GetNbBatchs return the number of batchs neededs to process all the shards according to the number of shards per batch
func (cg *ChunkGroup) GetNbBatchs() int {
	return int(math.Ceil(float64(cg.NbDataShards) / float64(cg.NbDataShardsPerBatch)))
}

//InitShards initalize the shard array and return the number of data shards and parity shards
func (cg *ChunkGroup) InitShards(chunkSize int, maxBatchSize int, ratioNumerator int, ratioDenominator int, bucketGenerator *BucketGenerator) (int, int, error) {
	cg.ChunkSize = chunkSize
	cg.PaddingSize = chunkSize - int(cg.FileSize%int64(chunkSize))

	cg.NbDataShards = int(math.Ceil(float64(cg.FileSize) / float64(chunkSize)))
	if cg.NbDataShards > 256 {
		return 0, 0, fmt.Errorf("Too many datashards, you have to increase the chunk size to at least %d bytes", cg.FileSize/256+1)
	}
	parityRatio := float64(ratioNumerator) / float64(ratioDenominator)
	if parityRatio < 1 {
		return 0, 0, fmt.Errorf("Ratio should be superior or equal to 1")
	}
	cg.NbParityShards = int(math.Ceil(float64(cg.NbDataShards) / parityRatio))

	cg.Shards = make([]*Shard, cg.NbDataShards+cg.NbParityShards)
	for i := range cg.Shards {
		cg.Shards[i] = NewShard(bucketGenerator.Next())
	}

	// determine batch size:
	batchMultiplier := 1
	for (batchMultiplier+1)*(ratioNumerator+ratioDenominator) <= maxBatchSize {
		batchMultiplier++
	}
	cg.NbDataShardsPerBatch = ratioNumerator * batchMultiplier
	cg.NbParityShardsPerBatch = ratioDenominator * batchMultiplier

	return cg.NbDataShards, cg.NbParityShards, nil
}

//ComputeShardCheckSum compute the check sum of a given shard, with a reader of the shard datas, return the checksum
func (cg *ChunkGroup) ComputeShardCheckSum(shardNum int, reader io.Reader) (string, error) {
	if shardNum >= len(cg.Shards) {
		return "", fmt.Errorf("There is only %d shards", len(cg.Shards))
	}
	return cg.Shards[shardNum].SetCheckSum(reader), nil
}

//GenerateNonce generate a nonce for a given shard, return the nonce
func (cg *ChunkGroup) GenerateNonce(shardNum int, nonceSize int) ([]byte, error) {
	if shardNum >= len(cg.Shards) {
		return nil, fmt.Errorf("There is only %d shards", len(cg.Shards))
	}
	return cg.Shards[shardNum].GenerateNonce(nonceSize)
}

// GetShardNum return the number of the shard in the shard arrays according to the number of the batch and the position of the shard in the batch
func (cg *ChunkGroup) GetShardNum(batchNum int, iterationNum int) int {
	var shardNum int
	nbDataShardsInBatch := cg.NbDataShardsPerBatch
	if batchNum == cg.GetNbBatchs()-1 && cg.NbDataShards%cg.NbDataShardsPerBatch != 0 {
		nbDataShardsInBatch = cg.NbDataShards % cg.NbDataShardsPerBatch
	}
	if iterationNum < nbDataShardsInBatch {
		shardNum = batchNum*cg.NbDataShardsPerBatch + iterationNum
	} else {
		shardNum = cg.NbDataShards + batchNum*cg.NbParityShardsPerBatch + (iterationNum - nbDataShardsInBatch)
	}

	return shardNum
}

// IsReconstructible return true if the file can be reconstructed even with the given buckets unavailable, false otherwise
func (cg *ChunkGroup) IsReconstructible(missingBuckets []string) bool {
	missingBucketsMap := map[string]int{}
	for i := range missingBuckets {
		missingBucketsMap[missingBuckets[i]] = 0
	}

	batchNbDataShards := cg.NbDataShardsPerBatch
	batchNbParityShards := cg.NbParityShardsPerBatch
	nbBatchs := cg.GetNbBatchs()

	for i := 0; i < nbBatchs; i++ {
		if i == nbBatchs-1 {
			if cg.NbDataShards%batchNbDataShards != 0 {
				batchNbDataShards = cg.NbDataShards % batchNbDataShards
			}
			if cg.NbParityShards%batchNbParityShards != 0 {
				batchNbParityShards = cg.NbParityShards % batchNbParityShards
			}
		}
		nbShardsneeded := batchNbDataShards + batchNbParityShards - int(math.Ceil(float64(batchNbDataShards)*float64(batchNbDataShards)/float64(batchNbParityShards)))
		nbShardsAvailable := 0
		for j := 0; j < batchNbDataShards+batchNbParityShards; j++ {
			_, bucketName := cg.GetStorageInfo(cg.GetShardNum(i, j))
			if _, ok := missingBucketsMap[bucketName]; !ok {
				nbShardsAvailable++
			}
		}
		if nbShardsneeded > nbShardsAvailable {
			return false
		}
	}
	return true
}

// GetGCM return a gcm initialized with the cg.AesPassword
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

// Encrypt serialize the chunkGroup to JSON then generate a KeyInfo and use it to encrypt the chunkGroup, return the encrypted chunkGroup and the keyInfo
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

// DecryptChunkGroup use the keyInfo to decrypt the encryptedChunkGroup, then deserialize it from json, return a chunkGroup
func DecryptChunkGroup(encrypted []byte, ki *KeyInfo) (*ChunkGroup, error) {
	var cg ChunkGroup
	gcm, err := ki.GetGCM()
	if err != nil {
		return nil, fmt.Errorf("Failed to get GCM : %s", err.Error())
	}
	cgJSON, err := gcm.Open(nil, ki.GetNonce(), encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt chunkGroup : %s", err.Error())
	}
	err = serialize.FromJSON(cgJSON, &cg)
	if err != nil {
		return nil, fmt.Errorf("failed to unserialize the chunkGroup from JSON : %s", err.Error())
	}
	return &cg, nil
}

//ToString return a string representation on a chunckGroup ready to be displayed
func (cg *ChunkGroup) ToString() string {
	str := fmt.Sprintf("ChunkGroup : \n fileName       : %s\n date           :%s\n fileSize       : %d\n aesPassword    : %s\n buckets        : \n", cg.FileName, cg.Date, cg.FileSize, cg.AesPassword)
	for _, name := range cg.GetBucketNames() {
		str += fmt.Sprintf(" --->%s\n", name)
	}
	str += fmt.Sprintf(" nbDataShards   : %d\n nbParityShards : %d\n chunkSize      : %d\n paddingSize    : %d\n", cg.NbDataShards, cg.NbParityShards, cg.ChunkSize, cg.PaddingSize)
	for _, shard := range cg.Shards {
		str += shard.ToString()
		str += "\n"
	}
	return str
}

//
//
//
//------------------------------- KEYINFO ----------------------------------------------------------------------------

//KeyInfo ...
type KeyInfo struct {
	AesPassword string `json:"aespassword,omitempty"`
	Nonce       []byte `json:"nonce,omitempty"`
}

// NewKeyInfo retrurn a keyInfo struct with a random AES password generated
func NewKeyInfo() (*KeyInfo, error) {
	password, err := generateAesPassword(true)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate AES password : %s", err.Error())
	}
	ki := KeyInfo{
		AesPassword: password,
	}
	return &ki, nil
}

//GetNonce return the nonce
func (ki *KeyInfo) GetNonce() []byte {
	return ki.Nonce
}

// GetGCM return a gcm initialized with the keyInfo aesPassword
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

// Encrypt serialize iKeyInfot to JSON, then use the private RSA Key to encrypt it, return an encrypted KeyInfo
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

// DecryptKeyInfo use the private RSA Key to decrypt the encryptedKeyInfo, then deserialize it from json, return a KeyInfo
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

//ToString return a string representation on a keyInfo ready to be displayed
func (ki *KeyInfo) ToString() string {
	str := fmt.Sprintf("KeyInfo : \n aesPassword     : %s\n nonce           :%x\n", ki.AesPassword, ki.Nonce)
	return str
}
