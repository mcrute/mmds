# Mock Metadata Service

This software is still heavily a work-in-progress. The IAM functionality should
work but other stuff may not. Bug reports and pull requests welcome.

This package provides a mock metadata service that returns plausible
responses for most of the metadata service endpoints. It also provides a
full IAM temporary credential endpoint that will assume an IAM role and
continually refresh the credentials as time passes. All AWS SDKs and most AWS
agents are able to work with this interface provided that it is bound to
169.254.169.254 port 80.

The daemon will attempt to bind two ports, port 80 on IP 169.245.169.254
provides the mock metadata service that is only available on the instance.
Additionally port 8998 will be bound on all interfaces for the administrative
service. The administrative service is used to boostrap the daemon and provide
health-checking.

## Setting up Interfaces
A loopback interface with IP address 169.254.169.254 is required by the daemon.
This can be accomplished on Linux with the following command:

```
sudo ip addr add 169.254.169.254/24 broadcast 169.254.169.255 dev lo:metadata
sudo ip link set dev lo:metadata up
sudo iptables -I INPUT 1 -d 169.254.0.0/16 ! -i lo -j DROP
```

*Note*: Do not bind this address to a publicly accessible interface or anyone
on the network will be able to use your AWS credentials.

## Startup
On startup the daemon will bind the ports described above and will wait for a
bootstrap credential. At this time it will accept requests for all endpoints
but will return an IAM failure response for the assumed role. Once bootstrapped
it will assume the requested IAM role and begin serving credentials.

## Health Checking
The daemon provides an HTTP endpoint on the administrative service to provide a
health status. The endpoint is `/status` and will return a JSON boolean (`true`
or `false`) to indicate that the daemon is running with a valid set of assumed
credentials.

## Bootstrapping
Once the daemon has assumed a role it will continue to re-assume that role
using the credentials provided by the AssumeRole API call. However, initial
credentials are required to bootstrap the role. These credentials only need
permissions to assume the role, all other permissions should be granted to the
role itself. These credentials should be provided to the administrative service
using a POST request with a JSON body.

The POST endpoint is `/bootstrap/creds` and is write-only. The JSON formatted
message should contain an access key ID, a secret access key and optionally, a
session token. The format is:

```
{
    "AccessKeyId": "AK...",
    "SecretAccessKey": "...",
    "Token": "..."
}
```

It is required to omit the token key or set the value to an empty string if no
token is available.

As soon as the bootstrap token is submitted the daemon will attempt to assume
the role it was started with and will begin allowing clients to reqeuest
credentials.

## Known Missing Features
Many of these feature either don't make sense outside of AWS or are not
possible to emulate.

Instance identity document signing. This can not be implemented because only
AWS has the private key. 

```
/latest/dynamic/instance-identity/signature
/latest/dynamic/instance-identity/pkcs7
/latest/dynamic/instance-identity/rsa2048
```

Block device mappings. May be available in the future.

```
/latest/meta-data/block-device-mapping/ami
/latest/meta-data/block-device-mapping/root
```

SSH keys. Will be available in a future release.

```
/latest/meta-data/public-keys/
/latest/meta-data/public-keys/0/openssh-key
```

Network interface mapping. May be available in the future.
```
/latest/meta-data/network/interfaces/macs/
/latest/meta-data/network/interfaces/macs/{mac}/device-number
/latest/meta-data/network/interfaces/macs/{mac}/interface-id
/latest/meta-data/network/interfaces/macs/{mac}/local-hostname
/latest/meta-data/network/interfaces/macs/{mac}/local-ipv4s
/latest/meta-data/network/interfaces/macs/{mac}/mac
/latest/meta-data/network/interfaces/macs/{mac}/owner-id
/latest/meta-data/network/interfaces/macs/{mac}/security-group-ids
/latest/meta-data/network/interfaces/macs/{mac}/security-groups
/latest/meta-data/network/interfaces/macs/{mac}/subnet-id
/latest/meta-data/network/interfaces/macs/{mac}/subnet-ipv4-cidr-block
/latest/meta-data/network/interfaces/macs/{mac}/vpc-id
/latest/meta-data/network/interfaces/macs/{mac}/vpc-ipv4-cidr-block
/latest/meta-data/network/interfaces/macs/{mac}/vpc-ipv4-cidr-blocks
/latest/meta-data/network/interfaces/macs/{mac}/vpc-ipv6-cidr-blocks
```
