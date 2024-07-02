# ACME

A minimal fuss library to create TLS certificates using Let's Encrypt or any other ACME V02 certificate provider.  Supports HTTP-01 and DNS-01 challenges.

## Create Certificate With HTTP-01 Challenge

Create a certificate using the HTTP-01 challenge.  By default this will launch a new HttpServer on the local machine 
serve the challenge files.  In this case, the code must be run from a machine that is publically accessible at all of the given host(s).  
You can supply your own `serveChallengeFile` and `removeChallengeFile` functions arrange another means of serving the file if needed.

``` dart
var certs = await acmeHttp01Challenge(
    hosts: ['mysite.com'], 
    email: "me@mysite.com",
    termsOfServiceAgreed: true,
);

certs.publicPem;
certs.privatePem;
```


## Create Certificate With DNS-01 Challenge

Create a certificate using the HTTP-01 challenge.  You will need to supply the functions [createDnsTxtRecord] and [removeDnsTxtRecord]
to arrage adding and removing DNS records.  This could be as simple as printing the value to stdout and waiting for a user to
manually add the record, or more likely API call to your DNS provider.  The value you return from [createDnsTxtRecord] will be
be passed to [removeDnsTxtRecord] for your convieniance.  This value is not used by this library.  It could be recordId identifier,
an AuthenticatedDnsClient or any other object that aids in cleanup.  It may be ignored completly if not needed for your implementation.

``` dart
var certs = await acmeDns01Challenge(
    hosts: ['mysite.com'], 
    email: "me@mysite.com",
    termsOfServiceAgreed: true,
    createDnsTxtRecord: (name, value) {
        // Create a TXT record on your DNS server
        // Optionally return a recordId of any type for later removal
    }, 
    removeDnsTxtRecord: (recordId) {
        // Remove the TXT record using the returned recordId
    },
);

certs.publicPem;
certs.privatePem;
```

See `example/cloud_flare.dart` and `exampple/main.dart` for a reference implementation of `createDnsTxtRecord` and `removeDnsTxtRecord`.

## Using the certificates

Certificates can be accessed from `certs.publicPem` and `certs.privatePem`.  These are string can can easily be stored to a file, distributed to a remote server, saved to a database, or otherwise deployed as needed.

See below for an example of how to start a dart server using the certfiicates.


``` dart
  // Start a Secure Server
  var server = await HttpServer.bindSecure(
    InternetAddress.anyIPv4,
    443,
    SecurityContext()
    ..useCertificateChainBytes(utf8.encode(certs.publicPem))
    ..usePrivateKeyBytes(utf8.encode(certs.privatePem))
  );

```

## Multiple Hosts And Wild Card Domains

You can create a certificate for multiple hosts, including wildcard domains.  See acme acme for details

``` Dart
await acmeDns01Challenge(
    hosts: ["mysite.org", "deeply.nested.subdomain.at.mysite.org", "*.api.mysite.org", "mysite.com"], 
    account: account,
    createDnsTxtRecord: createDnsTxtRecord,
    removeDnsTxtRecord: removeDnsTxtRecord
);
```
In this example:

+ `mysite.org`: Secures the main domain, but no sub-domains
+ `deeply.nested.subdomain.at.mysite.org`: Secures a specific deeply nested subdomain.
+ `*.api.mysite.org`: Secures all subdomains under `api.mysite.org` (e.g., `v1.api.mysite.org`, `v2.api.mysite.org`).  Only supported for DNS-01 challenges.
+ `mysite.com`: Secures another main domain.

