# ACME

A minimal fuss library to create TLS certificates using Let's Encrypt or any other ACME V02 certificate provider.  Supports HTTP-01 and DNS-01 challenges.

## Create Certificate With HTTP-01 Challenge

Create a certificate using the HTTP-01 challenge.  By default this will launch a new HttpServer on the local machine serve the challenge files.  In this case, the code must be run from a machine that is publically accessible at all of the given host(s). You can optionally supply your own `serveChallengeFile` and `removeChallengeFile` functions to arrange another means of serving the file if needed.

``` dart
var certs = await acmeHttp01Challenge(
    hosts: ['mysite.com'], 
    email: "me@mysite.com",
    termsOfServiceAgreed: true,
);

// Use the certs
certs.publicPem;
certs.privatePem;
```


## Create Certificate With DNS-01 Challenge

You will need to supply the functions [createDnsTxtRecord] and [removeDnsTxtRecord]
to arrage adding and removing DNS records.  This could be as simple as printing the value to stdout and waiting for a user to manually add the record, or more likely, an API call to your DNS provider.  The value you return from [createDnsTxtRecord] will be be passed to [removeDnsTxtRecord] for your convieniance.  This value is not used by this library.  It could be record identifier, an authenticated dns client or any other object that aids in cleanup.

``` dart
var certs = await acmeDns01Challenge(
    hosts: ['mysite.com'], 
    email: "me@mysite.com",
    termsOfServiceAgreed: true,
    createDnsTxtRecord: (name, value) {
        // Create a TXT record on your DNS server
        // The value retured will be passed to [removeDnsTxtRecord]
    }, 
    removeDnsTxtRecord: (recordId) {
        // Remove the TXT record
    },
);

certs.publicPem;
certs.privatePem;
```

See `example/cloud_flare.dart` for a reference implementation of `createDnsTxtRecord` and `removeDnsTxtRecord`.

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

  /// Serve a sample document
  server.listen((HttpRequest request) {
    var parts = request.uri.pathSegments;
    if (parts.isEmpty || parts.singleOrNull == "index.html") {
      request.response
        ..statusCode = HttpStatus.ok
        ..headers.contentType = ContentType.html
        ..write("""
<!DOCTYPE html>
<html lang="en">
<body>
    <h1>Hello From HTTPS!</h1>
</body>
</html>
""");
    } else {
      request.response
        ..statusCode = HttpStatus.notFound
        ..write('Not Found');
    }
    request.response.close();
  });
```

## Multiple Hosts And Wild Card Domains

You can create a certificate to secure multiple sites, including wildcard domains.  See official ACME documentation for details.

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

