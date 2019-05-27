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
	"os"
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/safescale/utils"

	"github.com/klauspost/reedsolomon"
	log "github.com/sirupsen/logrus"
)

//Default chunk sizes that will used to spit files (in Bytes)
const (
	keyFilePathConst  = "$HOME/.safescale/rsa.key"
	chunkSizeConst    = int(10 * (1 << (10 * 2)))
	parityNumConst    = 4
	parityDenConst    = 4
	parityRatioConst  = parityNumConst / parityDenConst
	batchMaxSizeConst = 4
)

//go:generate mockgen -destination=../mocks/mock_dataapi.go -package=mocks github.com/CS-SI/SafeScale/safescale/server/handlers DataAPI

// DataAPI defines API to manipulate Data
type DataAPI interface {
	List(ctx context.Context) ([]string, []string, []int64, [][]string, error)
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

// Return the formated (and considered unique) keyFileName and metadataFileName linked to a fileName
func getFileNames(fileName string) (string, string) {
	hashedFileName := utils.Hash(strings.NewReader(fileName))
	metadataFileName := "meta-" + hashedFileName + ".bin"
	keyFileName := "key-" + hashedFileName + ".bin"
	return metadataFileName, keyFileName
}

func (handler *DataHandler) getBuckets() (map[string]objectstorage.Bucket, []string, []objectstorage.Bucket) {
	buckets := handler.storageServices.GetBuckets()
	bucketNames := []string{}
	bucketMap := map[string]objectstorage.Bucket{}
	for i := range buckets {
		bucketName := buckets[i].GetName()
		bucketNames = append(bucketNames, bucketName)
		bucketMap[bucketName] = buckets[i]
	}
	return bucketMap, bucketNames, buckets
}

func fetchChunkGroup(fileName string, buckets []objectstorage.Bucket) (*utils.ChunkGroup, error) {
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
		keyInfo, err = utils.DecryptKeyInfo(buffer.Bytes(), keyFilePathConst)
		if err != nil {
			return nil, err
		}
		break
	}
	if keyInfo == nil {
		return nil, fmt.Errorf("Failed to find the file '%s'", fileName)
	}

	buffer.Reset()
	_, err := buckets[i].ReadObject(metadataFileName, &buffer, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("Failed to read the chunkGroup from the bucket '%s' : %s", buckets[i].GetName(), err.Error())
	}
	chunkGroup, err := utils.DecryptChunkGroup(buffer.Bytes(), keyInfo)
	if err != nil {
		return nil, err
	}
	return chunkGroup, nil
}

//Push ...
func (handler *DataHandler) Push(ctx context.Context, fileLocalPath string, fileName string) error {
	log.Debugf(">>> safescale.server.handlers.DataHandler::Push(%s)", fileLocalPath)
	defer log.Debugf("<<< safescale.server.handlers.DataHandler::Push(%s)", fileLocalPath)
	//localFile inspection
	file, err := os.Open(fileLocalPath)
	if err != nil {
		return fmt.Errorf("Failed to open '%s' : %s", fileLocalPath, err.Error())
	}
	defer func() { // FIXME: Catch error later
		_ = file.Close()
	}()

	fileStats, err := file.Stat()
	if err != nil {
		return fmt.Errorf("Failed to get file '%s' stats : %s", fileLocalPath, err.Error())
	}
	fileSize := fileStats.Size()

	//Preprocess buckets info
	bucketMap, bucketNames, buckets := handler.getBuckets()
	bucketGenerator := utils.NewBucketGenerator(buckets)
	metadataFileName, keyInfoFileName := getFileNames(fileName)
	//Check if the file is not already present on one of the buckets
	for i := range buckets {
		_, err := buckets[i].GetObject(metadataFileName)
		if err == nil {
			return fmt.Errorf("An object named '%s' is already present in the bucket '%s'", fileName, buckets[i].GetName())
		}

	}
	//Create ChunkGroup
	chunkGroup, err := utils.NewChunkGroup(fileName, fileSize, bucketNames)
	if err != nil {
		return err
	}
	//initialize
	nbDataShards, nbParityShards, err := chunkGroup.InitShards(chunkSizeConst, batchMaxSizeConst, parityNumConst, parityDenConst, bucketGenerator)
	if err != nil {
		return err
	}
	nbBatchs := chunkGroup.GetNbBatchs()
	chunkSize, batchNbDataShards, batchNbParityShards := chunkGroup.GetBatchSizeInfo()
	shards := make([][]byte, batchNbDataShards+batchNbParityShards)
	for i := 0; i < batchNbDataShards+batchNbParityShards; i++ {
		shards[i] = make([]byte, chunkSize)
	}
	encryptedShards := make([][]byte, batchNbDataShards+batchNbParityShards)
	for i := 0; i < batchNbDataShards+batchNbParityShards; i++ {
		encryptedShards[i] = make([]byte, chunkGroup.GetEncryptedChunkSize())
	}

	//for each batch
	for i := 0; i < nbBatchs; i++ {
		log.Debugf("---------Start batch %d----------", i)
		// On the last batch the number of shards may vary
		if i == nbBatchs-1 {
			if nbDataShards%batchNbDataShards != 0 {
				batchNbDataShards = nbDataShards % batchNbDataShards
			}
			if nbParityShards%batchNbParityShards != 0 {
				batchNbParityShards = nbParityShards % batchNbParityShards
			}
			shards = shards[:batchNbDataShards+batchNbParityShards]
			encryptedShards = encryptedShards[:batchNbDataShards+batchNbParityShards]
		}
		//Read datas from file
		for j := 0; j < batchNbDataShards; j++ {
			nbBytes, err := file.Read(shards[j])
			if err != nil {
				return fmt.Errorf("Failed to read the %d-th shard bytes : %s", j, err.Error())
			}
			//padding
			if nbBytes != chunkSize {
				for k := nbBytes; k > chunkSize; k++ {
					shards[j][k] = 0
				}
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
		for j := range shards {
			shardNum := chunkGroup.GetShardNum(i, j)
			nonce, err := chunkGroup.GenerateNonce(shardNum, gcm.NonceSize())
			if err != nil {
				return fmt.Errorf("Failed to generate nonce : %s", err.Error())
			}
			encryptedShards[j] = gcm.Seal(nil, nonce, shards[j], nil)
			_, err = chunkGroup.ComputeShardCheckSum(shardNum, bytes.NewReader(encryptedShards[j]))
			if err != nil {
				return fmt.Errorf("Failed to compute the check sum of a shard : %s", err.Error())
			}
		}

		//push encrypted shards to the storage object
		var errChan chan error
		var wg sync.WaitGroup
		wg.Add(len(encryptedShards))
		for j := range encryptedShards {
			go func(j int) {
				shardName, shardBucketName := chunkGroup.GetStorageInfo(chunkGroup.GetShardNum(i, j))
				bucket := bucketMap[shardBucketName]
				_, err := bucket.WriteObject(shardName, bytes.NewReader(encryptedShards[j]), int64(len(encryptedShards[j])), nil)
				if err != nil {
					errChan <- fmt.Errorf("Failed to copy a shard on the bucket '%s' : %s", bucket.GetName(), err.Error())
					log.Errorf("Failed to copy a shard on the bucket '%s' : %s", bucket.GetName(), err.Error())
				}
				wg.Done()
			}(j)
		}
		wg.Wait()
		select {
		case err := <-errChan:
			return err
		default:
		}
	}
	//encrypt and push chunkGroup
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

	//encrypt and push keyInfo
	encryptedKeyInfo, err := keyInfo.Encrypt(keyFilePathConst)
	if err != nil {
		return fmt.Errorf("failed to encrypt the KeyInfo : %s", err.Error())
	}

	for i := range buckets {
		_, err = buckets[i].WriteObject(keyInfoFileName, bytes.NewReader(encryptedKeyInfo), int64(len(encryptedKeyInfo)), nil)
		if err != nil {
			return fmt.Errorf("Failed to copy keyInfo on the bucket '%s' : %s", buckets[i].GetName(), err.Error())
		}
	}

	return nil
}

//Get ...
func (handler *DataHandler) Get(ctx context.Context, fileLocalPath string, fileName string) error {
	log.Debugf(">>> safescale.server.handlers.DataHandler::Get(%s)", fileName)
	defer log.Debugf("<<< safescale.server.handlers.DataHandler::Get(%s)", fileName)

	// Check if the local file is available
	if _, err := os.Stat(fileLocalPath); err == nil {
		return fmt.Errorf("File '%s' already exists", fileLocalPath)
	}
	file, err := os.Create(fileLocalPath)
	if err != nil {
		return fmt.Errorf("Failed to create the file '%s' : %s", fileLocalPath, err.Error())
	}
	defer func() {
		// Suppres local file if Get didn't succeed
		if err != nil {
			if derr := os.Remove(fileLocalPath); derr != nil {
				log.Errorf("Failed to delete file '%s': %s", fileLocalPath, derr.Error())
			}
		} else {
			_ = file.Close() // FIXME: Catch error later
		}
	}()

	//Get file metadatas
	bucketMap, _, buckets := handler.getBuckets()
	chunkGroup, err := fetchChunkGroup(fileName, buckets)
	if err != nil {
		return fmt.Errorf("Failed to fetch chunk group : %s", err.Error())
	}

	//check if some buckets of the object storage are missing and then if the file can be reconstructed
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

	//initialize
	nbDataShards, nbParityShards := chunkGroup.GetNbShards()
	chunkSize, batchNbDataShards, batchNbParityShards := chunkGroup.GetBatchSizeInfo()
	nbBatchs := chunkGroup.GetNbBatchs()

	shards := make([][]byte, batchNbDataShards+batchNbParityShards)
	for i := 0; i < batchNbDataShards+batchNbParityShards; i++ {
		shards[i] = make([]byte, chunkSize)
	}
	encryptedShards := make([]bytes.Buffer, batchNbDataShards+batchNbParityShards)

	//For each batchs
	for i := 0; i < nbBatchs; i++ {
		log.Debugf("---------Start batch %d----------", i)
		// On the last batch the number of shards may vary
		if i == nbBatchs-1 {
			if nbDataShards%batchNbDataShards != 0 {
				batchNbDataShards = nbDataShards % batchNbDataShards
			}
			if nbParityShards%batchNbParityShards != 0 {
				batchNbParityShards = nbParityShards % batchNbParityShards
			}
			shards = shards[:batchNbDataShards+batchNbParityShards]
			encryptedShards = encryptedShards[:batchNbDataShards+batchNbParityShards]
		}

		//load encrypted shards
		var errChan chan error
		var wg sync.WaitGroup
		wg.Add(batchNbDataShards + batchNbParityShards)
		for j := 0; j < batchNbDataShards+batchNbParityShards; j++ {
			go func(j int) {
				encryptedShards[j].Reset()
				shardName, shardBucktName := chunkGroup.GetStorageInfo(chunkGroup.GetShardNum(i, j))
				bucket, ok := bucketMap[shardBucktName]
				var err error
				if ok {
					_, err = bucket.ReadObject(shardName, &encryptedShards[j], 0, 0)
					if err != nil {
						errChan <- fmt.Errorf("Failed to copy a shard from the bucket '%s' : %s", bucket.GetName(), err.Error())
						log.Errorf("Failed to copy a shard from the bucket '%s' : %s", bucket.GetName(), err.Error())
					}
				}
				wg.Done()
			}(j)
		}
		wg.Wait()
		select {
		case err := <-errChan:
			return err
		default:
		}

		//Check the encypted shards integrity with the check sum and remove corrupted ones
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

		//Decryp the encrypted shards
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

		//reconstruct the original chunk
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

		//store the chunk on the localFile
		for j := 0; j < batchNbDataShards; j++ {
			//On the lash shard of the file, some padding could be added to let all shards have the same size, this padding should be removed
			if i == nbBatchs-1 && j == batchNbDataShards-1 {
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

	bucketMap, _, buckets := handler.getBuckets()
	metadataFileName, keyFileName := getFileNames(fileName)
	chunkGroup, err := fetchChunkGroup(fileName, buckets)
	if err != nil {
		return fmt.Errorf("Failed to fetch chunk group : %s", err.Error())
	}

	for _, bucketName := range chunkGroup.GetBucketNames() {
		if _, ok := bucketMap[bucketName]; !ok {
			return fmt.Errorf("Bucket '%s' is unknown", bucketName)
		}
	}
	nbDataShards, nbParityShards := chunkGroup.GetNbShards()

	var wg sync.WaitGroup
	wg.Add(nbDataShards + nbParityShards)
	for i := 0; i < nbDataShards+nbParityShards; i++ {
		go func(i int) {
			shardName, bucketName := chunkGroup.GetStorageInfo(i)
			err = bucketMap[bucketName].DeleteObject(shardName)
			if err != nil {
				log.Warnf("Failed to delete shard '%s' from bucket '%s'", shardName, bucketName)
			}
			wg.Done()
		}(i)
	}
	wg.Wait()

	for _, bucketName := range chunkGroup.GetBucketNames() {
		err = bucketMap[bucketName].DeleteObject(metadataFileName)
		if err != nil {
			log.Warnf("Failed to delete chunkGroup '%s' from bucket '%s'", metadataFileName, bucketName)
		}
		err = bucketMap[bucketName].DeleteObject(keyFileName)
		if err != nil {
			log.Warnf("Failed to delete keyInfo '%s' from bucket '%s'", keyFileName, bucketName)
		}
	}

	return nil
}

// List returns []fileName []UploadDate []fileSize [][]buckets, error
func (handler *DataHandler) List(ctx context.Context) ([]string, []string, []int64, [][]string, error) {
	log.Debugf(">>> safescale.server.handlers.DataHandler::List()")
	defer log.Debugf("<<< safescale.server.handlers.DataHandler::List()")

	bucketMap, _, buckets := handler.getBuckets()

	keyInfosMap := map[string][]string{}
	for i := range buckets {
		files, err := buckets[i].List("", "key-")
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("Failed to list objects of bucket '%s' : %s", buckets[i].GetName(), err.Error())
		}
		for j := range files {
			keyInfoFileName := files[j]
			keyInfosMap[keyInfoFileName] = append(keyInfosMap[keyInfoFileName], buckets[i].GetName())
		}
	}

	var buffer bytes.Buffer
	fileNames := []string{}
	uploadDates := []string{}
	fileSizes := []int64{}
	fileBuckets := [][]string{}

	for keyInfoFileName, bucketNames := range keyInfosMap {
		chunkGroupFileName := "meta-" + strings.Split(keyInfoFileName, "-")[1]
		//Load & decrypt KeyInfo
		buffer.Reset()
		_, err := bucketMap[bucketNames[0]].ReadObject(keyInfoFileName, &buffer, 0, 0)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("Failed to read the keyInfo from the bucket '%s' : %s", bucketNames[0], err.Error())
		}
		keyInfo, err := utils.DecryptKeyInfo(buffer.Bytes(), keyFilePathConst)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		//Load & decrypt ChunkGroup
		buffer.Reset()
		_, err = bucketMap[bucketNames[0]].ReadObject(chunkGroupFileName, &buffer, 0, 0)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("Failed to read the chunkGroup from the bucket '%s' : %s", bucketNames[0], err.Error())
		}
		chunkGroup, err := utils.DecryptChunkGroup(buffer.Bytes(), keyInfo)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		//Check if all needed buckets are known
		ok := true
		for _, cgBucketName := range chunkGroup.GetBucketNames() {
			if _, ok := bucketMap[cgBucketName]; !ok {
				break
			}
		}
		if !ok {
			continue
		}
		//fulfill output arrays
		fileName, uploadDate, fileSize := chunkGroup.GetFileInfos()
		fileNames = append(fileNames, fileName)
		uploadDates = append(uploadDates, uploadDate)
		fileSizes = append(fileSizes, fileSize)
		fileBuckets = append(fileBuckets, bucketNames)
	}

	return fileNames, uploadDates, fileSizes, fileBuckets, nil
}
