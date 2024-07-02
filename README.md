# ACME

A minimal fuss library to create TLS certificates using Let's Encrypt or any other ACME V02 certificate provider.  Currently, only DNS-01 challenges are supported.

## Create Certificate

``` dart
var certs = await acmeDns01Challenge(
    hosts: ['mysite.com'], 
    email: "me@mysite.com",
    termsOfServiceAgreed: true,
    createDnsTxtRecord: (name, value) {
        // Create a TXT record on your DNS server
        // Optionally return a recordId of any type for later removal
    }, 
    removeDnsRecord: (recordId) {
        // Remove the TXT record using the returned recordId
    },
);

certs.publicPem;
certs.privatePem;
```

See `example/cloud_flare.dart` and `exampple/main.dart` for a reference implementation of `createDnsTxtRecord` and `removeDnsRecord`.

## Using the certificates

Once certificates are created thay can be used to start a server.  `certs.publicPem` and `certs.privatePem` are strings, and can easily be stored to a file or database as needed for long term storage.

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

You can create a certificate for multiple hosts, including wildcard domains.  See acme refernce for details

``` Dart
await acmeDns01Challenge(
    hosts: ["mysite.org", "deeply.nested.subdomain.at.mysite.org", "*.api.mysite.org", "mysite.com"], 
    account: account,
    createDnsTxtRecord: createDnsTxtRecord,
    removeDnsRecord: removeDnsRecord
);
```
In this example:

+ `mysite.org`: Secures the main domain, but no sub-domains
+ `deeply.nested.subdomain.at.mysite.org`: Secures a specific deeply nested subdomain.
+ `*.api.mysite.org`: Secures all subdomains under `api.mysite.org` (e.g., `v1.api.mysite.org`, `v2.api.mysite.org`).
+ `mysite.com`: Secures another main domain.

