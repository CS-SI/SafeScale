package s3

import (
	"github.com/aws/aws-sdk-go/aws"
	awss3 "github.com/aws/aws-sdk-go/service/s3"
)

//CreateContainer creates an object container
func CreateContainer(service *awss3.S3, name string, region string) error {
	input := &awss3.CreateBucketInput{
		Bucket: aws.String(name),
		CreateBucketConfiguration: &awss3.CreateBucketConfiguration{
			LocationConstraint: aws.String(region),
		},
	}

	_, err := service.CreateBucket(input)
	return err
}

//DeleteContainer deletes an object container
func DeleteContainer(service *awss3.S3, name string) error {
	input := &awss3.DeleteBucketInput{
		Bucket: aws.String(name),
	}
	_, err := service.DeleteBucket(input)
	return err
}

//ListContainers list object containers
func ListContainers(service *awss3.S3) ([]string, error) {
	input := &awss3.ListBucketsInput{}

	result, err := service.ListBuckets(input)
	if err != nil {
		return nil, err
	}
	buckets := []string{}
	for _, b := range result.Buckets {
		buckets = append(buckets, *b.Name)
	}
	return buckets, nil
}
