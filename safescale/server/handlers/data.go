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

package handlers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/safescale/utils"

	"github.com/klauspost/reedsolomon"
	log "github.com/sirupsen/logrus"
)

//Default chunk sizes that will used to spit files (in Bytes)
const (
	keyFilePath_Const  = "$HOME/.safescale/rsa.key"
	chunkSize_Const    = int(10 * (1 << (10 * 2)))
	parityNum_Const    = 4
	parityDen_Const    = 4
	parityRatio_Const  = parityNum_Const / parityDen_Const
	batchMaxSize_Const = 4
)

//go:generate mockgen -destination=../mocks/mock_dataapi.go -package=mocks github.com/CS-SI/SafeScale/safescale/server/handlers DataAPI

// DataAPI defines API to manipulate Data
type DataAPI interface {
	List(ctx context.Context) ([]string, []string, []int64, error)
	Push(ctx context.Context, fileLocalPath string, fileName string) error
	Get(ctx context.Context, fileLocalPath string, fileName string) error
	Delete(ctx context.Context, fileName string) error
}

// DataHandler bucket service
type DataHandler struct {
	storageServices *iaas.StorageServices
}

// NewDataHandler creates a Data service
func NewDataHandler(svc *iaas.StorageServices) DataAPI {
	return &DataHandler{storageServices: svc}
}

// func getShardNum(nbDataShards int, nbParityShards int, batchNbDataShards int, batchNbParityShards int, nbLoops int, batchNum int, shardBatchNum int) int {
// 	var shardNum int
// 	if batchNum == nbLoops-1 {
// 		if shardBatchNum < batchNbDataShards {
// 			shardNum = nbDataShards - batchNbDataShards + shardBatchNum
// 		} else {
// 			shardNum = nbDataShards + nbParityShards - batchNbParityShards + (shardBatchNum - batchNbDataShards)
// 		}
// 	} else {
// 		if shardBatchNum < batchNbDataShards {
// 			shardNum = batchNum*batchNbDataShards + shardBatchNum
// 		} else {
// 			shardNum = nbDataShards + batchNum*batchNbParityShards + (shardBatchNum - batchNbDataShards)
// 		}
// 	}
// 	return shardNum
// }

// Return the formated (and considered unique) keyFileName and metadataFileName linked to a fileName
func getFileNames(fileName string) (string, string) {
	hashedFileName := utils.Hash(strings.NewReader(fileName))
	metadataFileName := "meta-" + hashedFileName + ".bin"
	keyFileName := "key-" + hashedFileName + ".bin"
	return metadataFileName, keyFileName
}

//Push ...
func (handler *DataHandler) Push(ctx context.Context, fileLocalPath string, fileName string) error {
	log.Debugf(">>> safescale.server.handlers.DataHandler::Push(%s)", fileLocalPath)
	defer log.Debugf("<<< safescale.server.handlers.DataHandler::Push(%s)", fileLocalPath)

	//Preprocess buckets info
	bucketMap := handler.storageServices.GetBuckets()
	bucketNames := []string{}
	buckets := []objectstorage.Bucket{}
	for bucketName, bucket := range bucketMap {
		bucketNames = append(bucketNames, bucketName)
		buckets = append(buckets, bucket)
	}
	bucketGenerator := utils.NewBucketGenerator(buckets)

	metadataFileName, keyFileName := getFileNames(fileName)

	//Check if the file is not already present on one of the buckets
	for i := range buckets {
		_, err := buckets[i].GetObject(metadataFileName)
		if err == nil {
			return fmt.Errorf("An object named '%s' is already present in the bucket '%s'", fileName, buckets[i].GetName())
		}

	}

	//Load Data
	file, err := os.Open(fileLocalPath)
	if err != nil {
		return fmt.Errorf("Failed to open '%s' : %s", fileLocalPath, err.Error())
	}
	defer file.Close()

	fileStats, err := file.Stat()
	if err != nil {
		return fmt.Errorf("Failed to get file '%s' stats : %s", fileLocalPath, err.Error())
	}
	fileSize := fileStats.Size()

	//Create ChunkGroup
	chunkGroup, err := utils.NewChunkGroup(fileName, fileSize, bucketNames)
	if err != nil {
		return err
	}

	//By batch :
	batchMultiplier := 1
	for (batchMultiplier+1)*parityNum_Const <= batchMaxSize_Const {
		batchMultiplier++
	}
	batchNbDataShards := parityNum_Const * batchMultiplier
	batchNbParityShards := parityDen_Const * batchMultiplier

	shards := make([][]byte, batchNbDataShards+batchNbParityShards)
	for i := 0; i < batchNbDataShards+batchNbParityShards; i++ {
		//Consume memory (+- 0.05GB for a 0.01GB chunk)
		shards[i] = make([]byte, chunkSize_Const)
	}
	shardReaders := make([]io.Reader, batchNbDataShards+batchNbParityShards)
	encryptedShards := make([][]byte, batchNbDataShards+batchNbParityShards)
	for i := 0; i < batchNbDataShards+batchNbParityShards; i++ {
		//Consume memory (+- 0.05GB for a 0.01GB chunk)
		encryptedShards[i] = make([]byte, (chunkSize_Const/16+1)*16)
	}

	nbDataShards, nbParityShards, err := chunkGroup.InitShards(chunkSize_Const, batchNbDataShards, batchNbParityShards, bucketGenerator)
	if err != nil {
		return err
	}
	nbLoops := int(math.Ceil(float64(nbDataShards) / float64(batchNbDataShards)))

	for i := 0; i < nbLoops; i++ {
		log.Debugf("---------Start batch %d----------", i)
		// On the last batch the number of shards may vary
		if i == nbLoops-1 {
			if nbDataShards%batchNbDataShards != 0 {
				batchNbDataShards = nbDataShards % batchNbDataShards
			}
			if nbParityShards%batchNbParityShards != 0 {
				batchNbParityShards = nbParityShards % batchNbParityShards
			}
			shards = shards[:batchNbDataShards+batchNbParityShards]
			shardReaders = shardReaders[:batchNbDataShards+batchNbParityShards]
			encryptedShards = encryptedShards[:batchNbDataShards+batchNbParityShards]
		}
		//Read datas from file
		for j := 0; j < batchNbDataShards; j++ {
			n, err := file.Read(shards[j])
			if err != nil {
				return fmt.Errorf("Failed to read the %d-th shard bytes : %s", j, err.Error())
			}
			//padding
			if n != chunkSize_Const {
				for k := n; k > chunkSize_Const; k++ {
					shards[j][k] = 0
				}
				batchNbDataShards = j + 1
				batchNbParityShards = int(math.Ceil(float64(batchNbDataShards) * float64(parityDen_Const) / float64(parityNum_Const)))
			}
		}
		// Reed-Salomon encoding
		encoder, err := reedsolomon.New(batchNbDataShards, batchNbParityShards)
		if err != nil {
			return fmt.Errorf("Failed to create a reedsolomon Encoder : %s", err.Error())
		}
		err = encoder.Encode(shards)
		if err != nil {
			return fmt.Errorf("Failed to create a encode the file : %s", err.Error())
		}

		// Encrypt shards with AES 256
		gcm, err := chunkGroup.GetGCM()
		if err != nil {
			return err
		}
		nonceSize := gcm.NonceSize()
		for j := range shards {
			shardNum := chunkGroup.GetShardNum(i, j)
			nonce, err := chunkGroup.GenerateNonce(shardNum, nonceSize)
			if err != nil {
				return fmt.Errorf("Failed to generate nonce : %s", err.Error())
			}
			//Consume memory (+- 0.05GB for a 0.01GB chunk)
			encryptedShards[j] = gcm.Seal(nil, nonce, shards[j], nil)
			if _, err = chunkGroup.ComputeShardCheckSum(shardNum, bytes.NewReader(encryptedShards[j])); err != nil {
				return fmt.Errorf("Failed to compute the check sum of a shard : %s", err.Error())
			}
		}

		for j := range encryptedShards {
			shardName, shardBucketName := chunkGroup.GetStorageInfo(chunkGroup.GetShardNum(i, j))
			bucket := bucketMap[shardBucketName]
			//TODO-AJ parralelize writes !!
			_, err = bucket.WriteObject(shardName, bytes.NewReader(encryptedShards[j]), int64(len(encryptedShards[j])), nil)
			if err != nil {
				return fmt.Errorf("Failed to copy a shard on the bucket '%s' : %s", bucket.GetName(), err.Error())
			}
		}
	}
	encryptedChunkGroup, keyInfo, err := chunkGroup.Encrypt()
	if err != nil {
		return fmt.Errorf("failed to encrypt the chunk group : %s", err.Error())
	}
	for i := range buckets {
		_, err = buckets[i].WriteObject(metadataFileName, bytes.NewReader(encryptedChunkGroup), int64(len(encryptedChunkGroup)), nil)
		if err != nil {
			return fmt.Errorf("Failed to copy chunkGroup on the bucket '%s' : %s", buckets[i].GetName(), err.Error())
		}
	}

	encryptedKeyInfo, err := keyInfo.Encrypt(keyFilePath_Const)
	if err != nil {
		return fmt.Errorf("failed to encrypt the KeyInfo : %s", err.Error())
	}
	for i := range buckets {
		_, err = buckets[i].WriteObject(keyFileName, bytes.NewReader(encryptedKeyInfo), int64(len(encryptedKeyInfo)), nil)
		if err != nil {
			return fmt.Errorf("Failed to copy keyInfo on the bucket '%s' : %s", buckets[i].GetName(), err.Error())
		}
	}

	fmt.Println(keyInfo.ToString())

	return nil
}

//Get ...
func (handler *DataHandler) Get(ctx context.Context, fileLocalPath string, fileName string) error {
	log.Debugf(">>> safescale.server.handlers.DataHandler::Get(%s)", fileName)
	defer log.Debugf("<<< safescale.server.handlers.DataHandler::Get(%s)", fileName)

	if _, err := os.Stat(fileLocalPath); err == nil {
		return fmt.Errorf("File '%s' already exists", fileLocalPath)
	}
	file, err := os.Create(fileLocalPath)
	if err != nil {
		return fmt.Errorf("Failed to create the file '%s' : %s", fileLocalPath, err.Error())
	}

	bucketMap := handler.storageServices.GetBuckets()
	buckets := []objectstorage.Bucket{}
	for _, bucket := range bucketMap {
		buckets = append(buckets, bucket)
	}

	metadataFileName, keyFileName := getFileNames(fileName)

	var buffer bytes.Buffer
	var keyInfo *utils.KeyInfo
	var i int
	for i = range buckets {
		buffer.Reset()
		_, err := buckets[i].ReadObject(keyFileName, &buffer, 0, 0)
		if err != nil {
			continue
		}
		keyInfo, err = utils.DecryptKeyInfo(buffer.Bytes(), keyFilePath_Const)
		if err != nil {
			return err
		}
		break
	}
	if keyInfo == nil {
		return fmt.Errorf("Failed to find the file '%s'", fileName)
	}

	buffer.Reset()
	_, err = buckets[i].ReadObject(metadataFileName, &buffer, 0, 0)
	if err != nil {
		return fmt.Errorf("Failed to read the chunkGroup from the bucket '%s' : %s", buckets[i].GetName(), err.Error())
	}
	chunkGroup, err := utils.DecryptChunkGroup(buffer.Bytes(), keyInfo)
	if err != nil {
		return err
	}

	missingBuckets := []string{}
	for _, bucketName := range chunkGroup.GetBucketNames() {
		if _, ok := bucketMap[bucketName]; !ok {
			missingBuckets = append(missingBuckets, bucketName)
		}
	}
	if len(missingBuckets) != 0 {
		if !chunkGroup.IsReconstructible(missingBuckets) {
			return fmt.Errorf("Too much shards are missing to reconstruct the file '%s'", fileName)
		}
	}

	nbDataShards, nbParityShards := chunkGroup.GetNbShards()
	chunkSize, batchNbDataShards, batchNbParityShards := chunkGroup.GetBatchSizeInfo()
	nbLoops := int(math.Ceil(float64(nbDataShards) / float64(batchNbDataShards)))

	shards := make([][]byte, batchNbDataShards+batchNbParityShards)
	for i := 0; i < batchNbDataShards+batchNbParityShards; i++ {
		//Consume memory (+- 0.05GB for a 0.01GB chunk)
		shards[i] = make([]byte, chunkSize)
	}
	shardReaders := make([]io.Reader, batchNbDataShards+batchNbParityShards)
	encryptedShards := make([]bytes.Buffer, batchNbDataShards+batchNbParityShards)

	for i := 0; i < nbLoops; i++ {
		log.Debugf("---------Start batch %d----------", i)
		// On the last batch the number of shards may vary
		if i == nbLoops-1 {
			if nbDataShards%batchNbDataShards != 0 {
				batchNbDataShards = nbDataShards % batchNbDataShards
			}
			if nbParityShards%batchNbParityShards != 0 {
				batchNbParityShards = nbParityShards % batchNbParityShards
			}
			shards = shards[:batchNbDataShards+batchNbParityShards]
			shardReaders = shardReaders[:batchNbDataShards+batchNbParityShards]
			encryptedShards = encryptedShards[:batchNbDataShards+batchNbParityShards]
		}

		for j := 0; j < batchNbDataShards+batchNbParityShards; j++ {
			shardName, shardBucktName := chunkGroup.GetStorageInfo(chunkGroup.GetShardNum(i, j))
			encryptedShards[j].Reset()
			bucket, ok := bucketMap[shardBucktName]
			//TODO-AJ parralelize Reads !!
			if ok {
				_, err = bucket.ReadObject(shardName, &encryptedShards[j], 0, 0)
				if err != nil {
					return fmt.Errorf("Failed to copy a shard from the bucket '%s' : %s", bucket.GetName(), err.Error())
				}
			}
		}

		for j := 0; j < batchNbDataShards+batchNbParityShards; j++ {
			if encryptedShards[j].Len() != 0 {
				checkSum := chunkGroup.GetCheckSum(chunkGroup.GetShardNum(i, j))
				computedCheckSum := utils.Hash(bytes.NewReader(encryptedShards[j].Bytes()))
				if checkSum != computedCheckSum {
					log.Warnf("%d-th shard of the batch corrupted, will be reconstructed", j)
					encryptedShards[j].Reset()
				}
			}
		}

		for j := 0; j < batchNbDataShards+batchNbParityShards; j++ {
			if encryptedShards[j].Len() != 0 {
				nonce := chunkGroup.GetNonce(chunkGroup.GetShardNum(i, j))
				gcm, err := chunkGroup.GetGCM()
				shards[j], err = gcm.Open(nil, nonce, encryptedShards[j].Bytes(), nil)
				if err != nil {
					return fmt.Errorf("Failed to decrypt shard : %s", err.Error())
				}
			} else {
				log.Warnf("%d-th shard of the batch missing, will be reconstructed", j)
				shards[j] = nil
			}
		}

		encoder, err := reedsolomon.New(batchNbDataShards, batchNbParityShards)
		if err != nil {
			return fmt.Errorf("Failed to create a reedsolomon Encoder : %s", err.Error())
		}
		err = encoder.Reconstruct(shards)
		if err != nil {
			return fmt.Errorf("Failed to reconstruct the file : %s", err.Error())
		}
		ok, err := encoder.Verify(shards)
		if err != nil {
			return fmt.Errorf("Failed to verify the file reconstrution : %s", err.Error())
		} else if !ok {
			return fmt.Errorf("Reconstruction verification failed")
		}
		for j := 0; j < batchNbDataShards; j++ {
			if i == nbLoops-1 && j == batchNbDataShards-1 {
				shards[j] = shards[j][:chunkSize-chunkGroup.GetPaddingSize()]
			}
			_, err := file.Write(shards[j])
			if err != nil {
				return fmt.Errorf("Failed to write a shard to the file '%s' : %s", fileLocalPath, err.Error())
			}
		}
	}
	return nil
}

// Delete ...
func (handler *DataHandler) Delete(ctx context.Context, fileName string) error {
	log.Debugf(">>> safescale.server.handlers.DataHandler::Delete(%s)", fileName)
	defer log.Debugf("<<< safescale.server.handlers.DataHandler::Delete(%s)", fileName)

	bucketMap := handler.storageServices.GetBuckets()
	buckets := []objectstorage.Bucket{}
	for _, bucket := range bucketMap {
		buckets = append(buckets, bucket)
	}

	metadataFileName, keyFileName := getFileNames(fileName)

	var buffer bytes.Buffer
	var keyInfo *utils.KeyInfo
	var i int
	for i = range buckets {
		buffer.Reset()
		_, err := buckets[i].ReadObject(keyFileName, &buffer, 0, 0)
		if err != nil {
			continue
		}
		keyInfo, err = utils.DecryptKeyInfo(buffer.Bytes(), keyFilePath_Const)
		if err != nil {
			return err
		}
		break
	}
	if keyInfo == nil {
		return fmt.Errorf("Failed to find the file '%s'", fileName)
	}

	buffer.Reset()
	_, err := buckets[i].ReadObject(metadataFileName, &buffer, 0, 0)
	if err != nil {
		return fmt.Errorf("Failed to read the chunkGroup from the bucket '%s' : %s", buckets[i].GetName(), err.Error())
	}
	chunkGroup, err := utils.DecryptChunkGroup(buffer.Bytes(), keyInfo)
	if err != nil {
		return err
	}

	for _, bucketName := range chunkGroup.GetBucketNames() {
		if _, ok := bucketMap[bucketName]; !ok {
			return fmt.Errorf("Bucket '%s' is unknown", bucketName)
		}
	}
	nbDataShards, nbParityShards := chunkGroup.GetNbShards()
	for i := 0; i < nbDataShards+nbParityShards; i++ {
		shardName, bucketName := chunkGroup.GetStorageInfo(i)
		err = bucketMap[bucketName].DeleteObject(shardName)
		if err != nil {
			log.Warn("Failed to delete shard '%s' from bucket '%s'", shardName, bucketName)
		}
	}
	for _, bucketName := range chunkGroup.GetBucketNames() {
		err = bucketMap[bucketName].DeleteObject(metadataFileName)
		if err != nil {
			log.Warn("Failed to delete chunkGroup '%' from bucket '%s'", metadataFileName, bucketName)
		}
		err = bucketMap[bucketName].DeleteObject(keyFileName)
		if err != nil {
			log.Warn("Failed to delete keyInfo '%s' from bucket '%s'", keyFileName, bucketName)
		}
	}

	return nil
}

// List returns []fileName []UploadDate []fileSize error
func (handler *DataHandler) List(ctx context.Context) ([]string, []string, []int64, error) {
	log.Debugf(">>> safescale.server.handlers.DataHandler::List()")
	defer log.Debugf("<<< safescale.server.handlers.DataHandler::List()")

	bucketMap := handler.storageServices.GetBuckets()
	buckets := []objectstorage.Bucket{}
	for _, bucket := range bucketMap {
		buckets = append(buckets, bucket)
	}

	keyInfosMap := map[string]string{}
	for i := range buckets {
		files, err := buckets[i].List("", "key-")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("Failed to list objects of bucket '%s' : %s", buckets[i].GetName(), err.Error())
		}
		for j := range files {
			fileHash := strings.Split(strings.Split(files[j], "-")[1], ".")[0]
			if _, ok := keyInfosMap[fileHash]; !ok {
				keyInfosMap[fileHash] = buckets[i].GetName()
			}
		}
	}

	var (
		buffer             bytes.Buffer
		keyInfoFileName    string
		chunkGroupFileName string
		keyInfo            *utils.KeyInfo
		chunkGroup         *utils.ChunkGroup
	)
	fileNames := []string{}
	uploadDates := []string{}
	fileSizes := []int64{}

	for hashedName, bucketName := range keyInfosMap {
		keyInfoFileName = "key-" + hashedName + ".bin"
		chunkGroupFileName = "meta-" + hashedName + ".bin"
		//Load & decrypt KeyInfo
		buffer.Reset()
		_, err := bucketMap[bucketName].ReadObject(keyInfoFileName, &buffer, 0, 0)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("Failed to read the keyInfo from the bucket '%s' : %s", bucketName, err.Error())
		}
		keyInfo, err = utils.DecryptKeyInfo(buffer.Bytes(), keyFilePath_Const)
		if err != nil {
			return nil, nil, nil, err
		}
		//Load & decrypt ChunkGroup
		buffer.Reset()
		_, err = bucketMap[bucketName].ReadObject(chunkGroupFileName, &buffer, 0, 0)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("Failed to read the chunkGroup from the bucket '%s' : %s", bucketName, err.Error())
		}
		chunkGroup, err = utils.DecryptChunkGroup(buffer.Bytes(), keyInfo)
		if err != nil {
			return nil, nil, nil, err
		}
		//Check if all needed buckets are known
		unknownBucket := false
		for _, cgBucketName := range chunkGroup.GetBucketNames() {
			if _, ok := bucketMap[cgBucketName]; !ok {
				unknownBucket = true
			}
		}
		if unknownBucket {
			continue
		}
		//fulfill output arrays
		fileName, uploadDate, fileSize := chunkGroup.GetFileInfos()
		fileNames = append(fileNames, fileName)
		uploadDates = append(uploadDates, uploadDate)
		fileSizes = append(fileSizes, fileSize)
	}

	return fileNames, uploadDates, fileSizes, nil
}
