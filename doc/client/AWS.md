```
[[tenants]]
    client = "aws"
    name = "myAws"

    [tenants.identity]
        AccessKeyID = "ABCDEFGHIJK........."
        SecretAccessKey = "12345678abcdef.........................."
        auth_uri = "https://iam.amazonaws.com"

    [tenants.compute]
        S3 = "https://s3.eu-central-1.amazonaws.com"
        EC2 = "https://ec2.eu-central-1.amazonaws.com"
        SSM = "https://ssm.eu-central-1.amazonaws.com"

        Region = "eu-central-1"
        Zone = "eu-central-1a"

    [tenants.objectstorage]
        Type        = "s3"
        AccessKey = "ABCDEFGHIJK........."
        SecretKey = "12345678abcdef.........................."
        Region      = "eu-central-1"
```
