## GCP Workload Federation with Kerberos


This is a simple STS server which exchanges a kerberos token for GCP credential using [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation) client side tooling for cloud SDK.

GCP Workload Federation support a variety of source token types like OIDC, SAML, mTLS, AWS where the flow involves exchanging the source token type for a GCP credential.

This repo does something different:  the client sdk contacts your own on-prem STS server and provides it with a kerberos token.  The kerberos token is validated and the STS server issues another short-term JWT.  This JWT is sent back to the STS server which validates it and provides the actual `access_token` back to the client.

All this works with workload federation because you can specify the source credential type *and* the STS server to contact.  Take for example the following modified [GOOGLE_APPLICATION_CREDENTIAL](https://cloud.google.com/iam/docs/workload-identity-federation-with-other-providers#download-cred-config) file for workload federation:

```json
{
  "universe_domain": "googleapis.com",
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/123456787/locations/global/workloadIdentityPools/fake-oidc-pool-foo/providers/fake-oidc-provider-foo",
  "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_url": "https://linux.domain.com:9080/v1/token",
  "credential_source": {
    "executable": {
      "command": "curl -s  --negotiate -u : --cacert root-ca.crt  https://linux.domain.com:9080/authenticate",
      "timeout_millis": 5000
    }
  }
}
```

What this file says to the cloud sdk is: "run the executable curl command, then take the output and send it to the token_url.  Then take whatever you get back there and use it to access GCP"

So, if the curl command uses kerberos token to authenticate to an STS server your'e running `HTTP/linux.domain.com` at the `/authentiate` endpoint, the the server can validate the kerberos token and know who the caller is.  

Then the server can mint a shot-term JWT with the callers's info in it and return it to the client SDK.

The Client SDK then takes the short term JWT and presents it to the `/v1/token` endpoint which validates it and returns an appropriate GCP `access_token`.

For more info, see:

[Simple DIY STS server Google Cloud Application Default Credential](https://gist.github.com/salrashid123/105b1cf7af103219bd4cdfa435046bd8)

![images/kerberos_sts.png](images/kerberos_sts.png)


>>> This repo is **NOT** supported by google.  its just a random idea

---

#### Setup

In this setup, we will run a KDC and a client VM on GCP (its easier to demo like this)

- 1. Create two debian vms:  `kdc` and `kclient` in `us-central-1a`


```bash
gcloud compute instances create kdc \
     --image-family=debian-11  \
	  --image-project=debian-cloud  --zone=us-central1-a 

gcloud compute instances create kclient \
     --image-family=debian-11  \
	  --image-project=debian-cloud  --zone=us-central1-a 	  
```

#### KDC

On the KDC, install the kerberos server, i used REALM=`DOMAIN.COM` here.  


```bash
$ sudo apt-get update
$ sudo apt install krb5-kdc krb5-admin-server
# set REALM to DOMAIN.COM
### replace $PROJECT with your projectID
## and Admin Host to : kdc.us-central1-a.c.$PROJECT.internal


### initialize the realm with a root password
$ sudo krb5_newrealm
```

Now edit `/etc/krb5.conf` with the following.  Again, remember to change `$PROJECT`

```conf
[logging]
    kdc = CONSOLE
    kdc = SYSLOG:INFO:DAEMON


[libdefaults]
	default_realm = DOMAIN.COM

	kdc_timesync = 1
	ccache_type = 4
	forwardable = true
	proxiable = true
	rdns = false

	fcc-mit-ticketflags = true

[realms]
	DOMAIN.COM = {
		kdc = kdc.us-central1-a.c.$PROJECT.internal
		admin_server = kdc.us-central1-a.c.$PROJECT.internal

		disable_pac = true
	}

[domain_realm]
    .domain.com = DOMAIN.COM
```

Now restart the services

```bash
sudo systemctl restart krb5-admin-server.service
sudo systemctl restart krb5-kdc.service
```

Create the principals:  

- `client1`: this is the sdk client system

- `HTTP/linux.domain.com`:  this is the sts server that hosts both `/authenticate` and the `/v1/token` endpoint.  These can be different server but the `/authenticate` endpoint must be running on this service principal hostname

```bash
root@kdc:~# kadmin.local 
	Authenticating as principal root/admin@DOMAIN.COM with password.

kadmin.local:  addprinc client1
kadmin.local:  addprinc HTTP/linux.domain.com@DOMAIN.COM

kadmin.local:  listprincs
		HTTP/linux.domain.com@DOMAIN.COM
		K/M@DOMAIN.COM
		client1@DOMAIN.COM
		kadmin/admin@DOMAIN.COM
		kadmin/changepw@DOMAIN.COM
		krbtgt/DOMAIN.COM@DOMAIN.COM
```

Now create a keytab (`http.keytab`) on the server

```bash
$ ktutil
    add_entry -password -p HTTP/linux.domain.com@DOMAIN.COM -k 1 -f aes256-cts-hmac-sha1-96
    wkt http.keytab

$ ktutil 
	ktutil:  rkt http.keytab
	ktutil:  list
			slot KVNO Principal
			---- ---- ---------------------------------------------------------------------
			1    1 HTTP/linux.domain.com@DOMAIN.COM
```

Now on the server, [install golang](https://go.dev/doc/install) and clone the repository

```bash
git clone https://github.com/salrashid123/gcp_workload_federation_kerberos/
cd gcp_workload_federation_kerberos/

go run main.go
```

This starts up the sts server with the kerberos enabled endpoint `/authentiate`, and the jwt-to-access_token issuer `/vi/token`

### Client

On the client vm, install the kerberos client library

```bash
$ sudo apt install krb5-user sssd-krb5 dnsutils
# set REALM to DOMAIN.COM
## as above replace $PROJECT
## and Admin Host to : kdc.us-central1-a.c.$PROJECT.internal

### login and get a service ticket for HTTP/linux.domain.com
#### # https://github.com/jcmturner/gokrb5/issues/545

$ kinit --no-request-pac -S HTTP/linux.domain.com@DOMAIN.COM client1@DOMAIN.COM


$ klist

	Ticket cache: FILE:/tmp/krb5cc_1000
	Default principal: client1@DOMAIN.COM

	Valid starting     Expires            Service principal
	11/26/24 11:29:29  11/27/24 11:29:29  HTTP/linux.domain.com@DOMAIN.COM
```

At this point you've got the necessary kerberos tokens.

Get the IP address of the server
```bash
$ export IP=`nslookup kdc.us-central1-a.c.$PROJECT.internal | awk '/^Address: / { print $2 }'`
$ echo $IP

### use curl to access the endpoint
$ curl -s  --negotiate -u : --resolve  linux.domain.com:9080:$IP --cacert root-ca.crt   https://linux.domain.com:9080/authenticate  | jq '.'
```

A trace would show the full `Negotiate` headers sent in:

```bash
$ curl -s  --negotiate -u : --resolve  linux.domain.com:9080:$IP --cacert root-ca.crt   https://linux.domain.com:9080/authenticate  | jq '.'

> GET /authenticate HTTP/1.1
> Host: linux.esodemoapp2.com:9080
> Authorization: Negotiate YIICVQYGKwYBBQUCoIICSTCCAkWgDTALBgkqhkiG9xIBAgKiggIyBIICLmCCAioGCSqGSIb3EgECAgEAboICGTCCAhWgAwIBBaEDAgEOogcDBQAgAAAAo4IBJ2GCASMwggEfoAMCAQWhERsPRVNPREVNT0FQUDIuQ09NoigwJqADAgEBoR8wHRsESFRUUBsVbGludXguZXNvZGVtb2FwcDIuY29to4HaMIHXoAMCARKhAwIBAaKBygSBx4bAtuGnUilUQysGkWSZpG27NmAXzI6ju0Yo7KJHYoWwbxx1RuuWh6VjwnpFNyL2KA4ssbxNIP+5Fvql2rhK/j1ucHelEnp7CVWxmiZMIM1HjYpJdVSnMSJ04xzdSgA1RCEYefu2mrrlUsizAxKXROuUXkKfmSBsAtVNPciuEBJ5tKIiIxcdyWNw9Ke48KO45RjiSuBMBHA/y6U8NV5rkqFvrfC/uwJ06zu4Itta1RFZEjo5y71z2TnI4KITECggDSW5Z8xKyD2kgdQwgdGgAwIBEqKByQSBxlbWEBR/yQ8wTrrzyuyw4kY+5sVcNVGamjs383nT4Yk9N+HGMi2EYO0QcTfAEUTxl2D48C/t51dwg3ilR0VFJTU1iP+USNMhl7p1pKOuaJghWaxgdx81kUZywWd74ZTxdT9vniTQ99eZ3Vx4ywjLOQrGrFvQ92Y7WICZustnKFdhwz+mv5Fsm3WalQug7EMOe5y1d7fNETga1jHrDmUcYjbzGWORM+c3QJ8Zpacm2FMt3Ch1SrTZ6svddNPhaxf2aHSUy8Gbbw==
> User-Agent: curl/7.88.1
> Accept: */*

HTTP/1.1 200 OK
< Www-Authenticate: Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg==
< Date: Mon, 25 Nov 2024 19:55:06 GMT
< Content-Length: 241
< Content-Type: text/html; charset=utf-8
```


you should see a JWT response.  What the server did was validated your kerberos token, then extracted the username from the token, minted a jwt with the user as the `subject` field in the jwt and sent it back

```json
{
  "version": 1,
  "success": true,
  "token_type": "urn:ietf:params:oauth:token-type:id_token",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2RpeV9zdHMiLCJhdWQiOlsiY2xpZW50MSJdLCJleHAiOjE3MzI2NDg1MDEsImlhdCI6MTczMjY0ODUwMCwiZG9tYWluIjoiRE9NQUlOLkNPTSIsInNlc3Npb25faWQiOiJlM2M3ZDAyMy1iZGM4LThlNTktYWEyMy1kODBlMmI4ZDRiMzciLCJhdXRoX3RpbWUiOjE3MzI2NDg1MDB9.hDs2OA0F2o9wS88xEDU724Q6BxA1qyMaF6dZHI2C3QSg177s72rxda1cjWizDWZetJtHE8pLCnBbtf3HMvEmM96aYxyeN0PrrKfRRILRHGKK_0z32DnTFO_etY1FVGpFEt63auNgd_CdglEnQwliCw1qgvqWfU1tN5PlLFm8o-Wrb8_XRjbmTfMD1vIlDdgvRcAoIIhzAY14vPW2m0imllwjjc5wUOOs8L6UtwRuvZzMKsfNY8_GMKzsl_0RI7361qK8uOJSAzetjI4f4RLqScLrjdfOkw7nQbQPcPRYy0RPEjqKb0sUmgxrhPBT1Of7yKAo3YK5z3uIDSht_eBs0A",
  "expiration_time": 1732648520
}
```

The decoded JWT has our user `client` and domain `DOMAIN.COM` encoded in it 

```json
{
  "alg": "RS256",
  "typ": "JWT"
}
{
  "iss": "https://diy_sts",
  "aud": [
    "client1"
  ],
  "exp": 1732648501,
  "iat": 1732648500,
  "domain": "DOMAIN.COM",
  "session_id": "e3c7d023-bdc8-8e59-aa23-d80e2b8d4b37",
  "auth_time": 1732648500
}
```

##### Using gcloud

if you want to use gcloud or our cloud sdk, its a bit more complicated over SSL since i'm using my own CA.

First thing is to set the host overrice.  The following internal IP is just mine, your value will be different for your KDC

```bash
$ cat /etc/hosts
10.128.15.232 linux.domain.com
```


Create the ADC config file. 

```bash
cat <<EOF >> sts-creds-file.json
{
  "universe_domain": "googleapis.com",
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/995081019036/locations/global/workloadIdentityPools/fake-oidc-pool-1/providers/fake-oidc-provider-1",
  "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_url": "https://linux.domain.com:9080/v1/token",
  "credential_source": {
    "executable": {
      "command": "curl -s  --negotiate -u : --cacert root-ca.crt  https://linux.domain.com:9080/authenticate",
      "timeout_millis": 5000
    }
  },
  "token_info_url": "https://sts.googleapis.com/v1/introspect"
}
EOF
```

Now wexport some variables and print the access token
```bash
export GOOGLE_APPLICATION_CREDENTIALS=`pwd`/sts-creds-file.json
export GOOGLE_CLOUD_PROJECT=your-project-id
export GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1
export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE=`pwd`/root-ca.crt


$ gcloud auth application-default print-access-token
some_token
```

the `some_token` is just a place holder and static token.  What you should be doing in main.go is figure out who the user is, then issue a token based on whatever ACL's you deem necessary.

you can even issue another workload federation token too (eg, instead of returning `some_token`, you actually review who the user again, then look at the `audience` and other fields from the STS config, then do another exchange with `sts.googleapis.com` for an actual workload federation token and return that)

For cloud SDK, again, since i'm using custom certs...

```bash
cat /etc/ssl/certs/ca-certificates.crt `pwd`/root-ca.crt > roots-combined.crt
export REQUESTS_CA_BUNDLE=`pwd`/roots-combined.crt

```

the code would look like

```python
from google.cloud import storage

# import logging
# import http
# http.client.HTTPConnection.debuglevel = 1
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True

storage_client = storage.Client('project')
bucket_name = "bucket"
file_name = "foo.txt"

bucket = storage_client.bucket(bucket_name)
blob = bucket.blob(file_name)
file_content = blob.download_as_string()
print(file_content)
```

As a wireshark trace end-to-end over http1.1:

```bash
wireshark trace.cap -otls.keylog_file:keylog.log
```

![images/authorization_header.png](images/authorization_header.png)


For more information about STS servers, see

- [Serverless Security Token Exchange Server(STS) and gRPC STS credentials](https://github.com/salrashid123/sts_server)
- [Security Token Service (STS) Credentials for HTTP and gRPC (rfc8693)](https://github.com/salrashid123/sts)
- [External Account Credentials (https://google.aip.dev/auth/4117)](https://google.aip.dev/auth/4117)
- [Certificate Bound Tokens using Security Token Exchange Server (STS)](https://github.com/salrashid123/cert_bound_sts_server)
- [Envoy WASM and LUA filters for Certificate Bound Tokens](https://github.com/salrashid123/envoy_cert_bound_token)
