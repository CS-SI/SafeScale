
# Create and configure a free Amazon account

First, you have to create a free Amazon account , it wll require a mail address, and a credit card (it's still free).
https://portal.aws.amazon.com/billing/signup

![SafeScale Infra](credentials.jpg "Credentials")

When it's created, login to console interface and configure your region (top right, in header bar)

![SafeScale Infra](region.png "Region")

Next step is to create credential that Safescale will use (as shown below)
https://console.aws.amazon.com/iam/home?#security_credential

# Install and configure Safescale

First, you have to set Amazon accesskey in Safescale configuration file.
Get bellow example and fill with your access keys to create your own file "tenants.toml"

```toml
[[tenants]]
    client = "aws"
    name = "MyFreeAWS"
    [tenants.identity]
        AccessKeyID = "<AccessKeyID>"
        SecretAccessKey = "<SecretAccessKey>"
        Username = ""
        Password = ""
    [tenants.compute]
        Region = "eu-west-3"
        Zone = "eu-west-3a"
    [tenants.objectstorage]
        Type = "s3"
        AccessKey = "<AccessKey>"
        SecretKey = "<SecretAccessKey>"
        Region = "<Region>"
```

To get binaries :

1. Get on github : https://github.com/CS-SI/SafeScale/releases
2. Compil : https://github.com/CS-SI/SafeScale/blob/master/doc/build
3. Compil with docker : After git checkout, run ./create-docker.sh -f (for that you need to install `docker-ce`)

Steps to launch daemon safescaled :
- Copy binaries on your client
- Launch daemon `safescaled` one time to create config dir
- Create a tenant.toml into `$HOME/.safescale` ($HOME/.safescale/tenants.toml ou /etc/safescale/tenants.toml)
- (optionally) Add env and aliases on your `.bashrc`
- export SAFESCALE_METADATA_SUFFIX="your trigram" 

# Create my own cluster with Safescale

First, we have to start Safescale demon and set tenants previously configured

## List tenants
```bash
safescale tenant ls
{"result":[{"name":"MyFreeAWS","provider":"aws"}],"status":"success"}
```

## Set current tenant

```bash
safescale tenant set MyFreeAWS
{"result":null,"status":"success"}
```

Create step by step, components for a host

## This creates a machine named gw-mynetwork acting as a gateway :
```bash
safescale network create --cidr 192.168.11.0/24 --sizing "cpu<=2,ram<=7,disk<=100" mynetwork
{"result":{"cidr":"192.168.11.0/24","id":"vpc-08f44cf1b70ccd659","name":"mynetwork","subnets":["mynetwork"]},"status":"success"}
```

## This retrieves information from the new host gw-mynetwork:
```bash
safescale host inspect gw-mynetwork
{"result":{"cpu":1,"creation_date":"2023-02-02T13:24:25Z","id":"i-0ba47463f8a4fd0b7","kvs":{"CreationDate":"2023-02-02T13:24:25Z","DeclaredInBucket":"0-safescale-b3a35c904fcce656410ad9b42889328f-afraid","Image":"ami-0b575d704a68bb8f3","ManagedBy":"safescale","Name":"gw-mynetwork","Revision":"e47dc4179827cf6798b9d1d5c85cc22a2a61b71b","Template":"c5.large","clusterID":"","type":"gateway"},"labels":[],"name":"gw-mynetwork","password":"+2erJ,42x39LF;,)","private_ip":"192.168.11.96","private_key":"-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAn9k22PFyoa5pZ9UJfLfswtK908O1VQc9QD/71LaYdlDwRnR/\nLM+zb7xh+L1QFjE/zaJpx800Q1YQ5qQtHOEanPDO/7oGRPwsgI9l9t5Yb2KlWHAP\nzwvlmAVJwpy05Jzn3VjuHNNTOpsU7u5vEE/VFmGuGQG7mVo3HdM4W9ky+Xf6LrVf\nEBxn/S74sqs5xwk2W9f/9T7JDVrG1OdgbdN6rEaFwoSb2mUupiliZD6ZEAb65Baz\nY7XR11bvPyhVnERXmHAfon4fFVNcJIe5lVbLCT5DZoteh+tmG/QofVsffR9qSM78\n/EA1EUVaJUR7tnQVEDg27l1VwXnMxpS3dwsa1QIDAQABAoIBAFFrrPpYEhG060/O\nPeTfMqQSAEsrduP2qgZeEQJKd+JcW+cnU9gZe8bAaA7xLyf+sgcmYUc6iRJ7dmRk\n3+3D43BpYKb1tFfTMz/QyxkyLE2gK6SegA7wemQy3V1ZwPJp0dj3gWIBanWBpOoH\nXV8rqtiZrLpkHZCBWW3BtwVh3wseeZoXwX7WAXBGECw9YuYtu+jyYa1qmqO0xi+a\nLV1naECLdA2z0/p8jd/4BFWnKBVKCyQ+rQe1AbSvM+Xcwv2Fxz1UbglrfjY79OER\n9KOlpNwmSQa7/EqjFLRkmyMWVNqXpXl517ZAWNyE9rUd2Ss5nMaySHHPz2CJNiio\nWGO6SMECgYEAzrJtoVbeVUSBk+ZuAi5RFj5e1fy4Ii3jaCd5ee1fadD+R68omW4U\n9vvGcDm9QFKuxGCgPso60QZq2e5B0h1TDz8dt3oxK7f6gR/oFLy0ei2c0lem2pr/\n0IhYwz/bAGZNfK6FSXGDzwMcPUXc88Lnbpxo9HFaDb6d+.....=\n-----END RSA PRIVATE KEY-----","public_ip":"13.37.68.78","ram":4,"state":2,"state_label":"Started","tags":[],"template":"c5.large"},"status":"success"}
```
Then you can access the machine with SSH with the user 'safescale' and the SSH key displayed in 'private_key'


# Cluster creation

## This creates a cluster of machines names mycluster
```bash
safescale cluster create -C Normal -F BOH --cidr 192.168.37.0/24 mycluster
{"result":{"admin_login":"cladm","admin_password":"/T;25P:59)Nk6KG)","cidr":"192.168.37.0/24","complexity":3,"complexity_label":"Normal","default_route_ip":"192.168.37.245","disabled_features":{},"endpoint_ip":"13.39.10.217","flavor":4,"flavor_label":"BOH","installed_features":{"features":[{"name":"docker"},{"name":"ansible"},{"name":"ansible-for-cluster"}]},"last_state":1,"last_state_label":"CS_NOMINAL","name":"mycluster","network_id":"vpc-0660bb4c985551f6a","nodes":{"masters":[{"id":"i-06281e96243885904","name":"mycluster-master-2","private_ip":"192.168.37.232"},{"id":"i-00c3247a9ec9249a9","name":"mycluster-master-1","private_ip":"192.168.37.90"}],"nodes":[{"id":"i-0c9a65b2145df8bd4","name":"mycluster-node-2","private_ip":"192.168.37.83"},{"id":"i-0ba2e4bf8d47a4a01","name":"mycluster-node-3","private_ip":"192.168.37.153"},{"id":"i-0a1948dc178cbebd0","name":"mycluster-node-1","private_ip":"192.168.37.55"}]},"primary_gateway_ip":"192.168.37.245","primary_public_ip":"13.39.10.217","remote_desktop":"no remote desktop available","subnet_id":"subnet-06f83149fd8e9f18a","tenants":"aws"},"status":"success"}
```

## To add one node to a cluster
```bash
safescale cluster expand mycluster
{"result":{"nodes":[{"cpu":2,"creation_date":"2023-02-02T14:25:10Z","id":"i-0eae2acb8840bfd77","kvs":[{"key":"CreationDate","value":"2023-02-02T14:25:10Z"},{"key":"DeclaredInBucket","value":"0-safescale-b3a35c904fcce656410ad9b42889328f-afraid"},{"key":"Revision","value":"e47dc4179827cf6798b9d1d5c85cc22a2a61b71b"},{"key":"Template","value":"c5.xlarge"},{"key":"clusterID","value":"a1876e8e-0c09-4182-bb6d-fedf2d254945"},{"key":"type","value":"node"},{"key":"Image","value":"ami-062f3e4f04af506a4"},{"key":"ManagedBy","value":"safescale"},{"key":"Name","value":"mycluster-node-6"}],"name":"mycluster-node-6","password":"rvPg,R4,65_3_J+8","private_ip":"192.168.37.54","private_key":"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAsK2XujbXWeywHzimsJFWz+IwfBkK5+dW82KkJ+UVJFAWTkUo\n9UTE6Fus73/XKJg7ItcBUR028hbzKulfCP8Oa0dw0wngoBwASh0EK+aWT92wPTXQ\nPTTZCzMMGDG3wTCf6EKzv4d6ChBPbJVVcLP0yMg23ICS3g3Hsk3NrwLjgVWf6gHi\n5Jzy/Sla/cYXYpMLa4FowXnK+UuL+waDyMNFmbQV/VYnjWHMoA4NHmqlKeveSgas\nNbeQs/1dYrqz1q/qBqEyjNid78pq/qG04LBbK4GnRGLAFukjb+KG6JCOHz/bqOAy\n71i0NHYqTjIrEAlkLRi2jUq1X6O4HJ3HKoXPOwIDAQABAoIBAQCM27muEu8amKPK\nIIZ1G0rVLoZtSiHxxfUC0lACJpf2fYtrF6SR9yPuBLkZsRi/Gq97FWPNYbdex4FT\nYwAL0h2S1kBTYPqfa/OnIv8iaRLJ1fsesfq18Z5hWW95EppoAfZbXGKmfsKDp4FL\nFrwpwK+WLFng7vko5F+j/nfP4kOz5lY3rHg2xcjCuYmI4qsnUMvjHfShXC0WDiHK\nG9cyUPxak1k1FxFHNYBDPY67P8iDY72I2UXBzvf1F2j9ilhFfH/4/+PJRhnICEXF\nwsT6usJO2ygju2EJq9+pwwF4F85Y3JJps3TlFfuPUmzQwfbWzIE6i6reylUopN7e\nQ931aRzRAoGBAOSyCZRoinVh7W852XbsNih0PIz4XSjluqjR71FQmD/G+n5Xcx70\nDe2875k7WFIhY9PX5UXLNU/i6VvIEqk94Bazxz0kepqCi9PihaxW0oScRYusUaRN\nI2GJbcMvOLAWHMtbGduhNnVZgKboms5cSMgDx5BJ7u1bHJlr0N9kAZKHAoGBAMXF\nq6i1SfIazmzYluoVKBVc4ENG0d/AHwNv+Aoiwjp+wihltil2rKSMwshj1pmwQCaG\n6Qhynm00wdJAIFXauehdWMsohutSCEPs8a2ioUjliZ+GIw5+2rYGi3F8K94SVXGx\n9fikz9KWzogxTLwNi1KayRe1lH+ZFMb5TMgjTGatAoGAVpVBIzrhEMfeiLmyJ2AO\nsQow0n5FZvJy1O+GV5bXzW2b8LFTGGj1zQg2/iCFs7KIhO+8Ecx5hqE2EFWTGxgd\n+vpdeDyTXmQGZFXinfjRAvvXKKY40qeRuZ+6OqdqIuB8TlFTXN+QKqWUG5z83xv5\nQiCMMYiMOLjB/yPelHTcU4kCgYEAvC9TH70hF5YaRcfyEdr/wR.....==\n-----END RSA PRIVATE KEY-----","ram":8,"state":2,"state_label":"Started","template":"c5.xlarge"}]},"status":"success"}
```

## To delete one node from a cluster
```bash
safescale cluster shrink mycluster
Are you sure you want to delete 1 node from Cluster mycluster ? (y/N): y
{"result":null,"status":"success"}
```

## To list all masters from a cluster
```bash
safescale cluster inspect mycluster | jq '.result.nodes.masters'
[
  {
    "id": "i-06281e96243885904",
    "name": "mycluster-master-2",
    "private_ip": "192.168.37.232"
  },
  {
    "id": "i-00c3247a9ec9249a9",
    "name": "mycluster-master-1",
    "private_ip": "192.168.37.90"
  }
]
```

## To get private IP addresses of these masters :
```bash
safescale cluster inspect mycluster | jq '.result.nodes.masters[].private_ip'
"192.168.37.232"
"192.168.37.90"
```

If you want to remove `""` around the results, you need to add `-r` option after `jq` command
```bash
safescale cluster inspect mycluster | jq -r '.result.nodes.masters[].private_ip'
192.168.37.232
192.168.37.90
```
## To list all nodes from a cluster
```bash
safescale cluster inspect mycluster | jq '.result.nodes.nodes'
[
  {
    "id": "i-0c9a65b2145df8bd4",
    "name": "mycluster-node-2",
    "private_ip": "192.168.37.83"
  },
  {
    "id": "i-0ba2e4bf8d47a4a01",
    "name": "mycluster-node-3",
    "private_ip": "192.168.37.153"
  },
  {
    "id": "i-0a1948dc178cbebd0",
    "name": "mycluster-node-1",
    "private_ip": "192.168.37.55"
  }
]
```
