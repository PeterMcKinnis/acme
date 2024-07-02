import 'dart:convert';
import 'dart:io';

import 'package:acme/acme.dart';

void main() async {
  // Create a certificate for one or more hosts
  var hosts = [
    "mysite.com",
  ];

  // Create the certificate using DNS-01 challenge
  var certs = await acmeHttp01Challenge(
      hosts: hosts, email: "my_email@mysite.com", termsOfServiceAgreed: true);

  // Start the secure server
  // Start Authenticated Server
  var server = await HttpServer.bindSecure(
    InternetAddress.anyIPv4,
    443,
    SecurityContext()
      ..useCertificateChainBytes(utf8.encode(certs.publicPem))
      ..usePrivateKeyBytes(utf8.encode(certs.privatePem)),
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

  print("Site is live.  Visit now at https://${hosts.single}");
}
