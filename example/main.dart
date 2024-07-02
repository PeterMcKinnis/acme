import 'dart:convert';
import 'dart:io';
import 'package:acme/acme.dart';
import 'cloud_flare.dart';

void main() async {
  // Create a certificate for one or more hosts
  var hosts = [
    "mysite.org",
    "deeply.nested.subdomain.at.mysite.org",
    "*.api.mysite.org",
    "mysite.com"
  ];

  // Create the certificate using DNS-01 challenge
  var certs = await acmeDns01Challenge(
    hosts: hosts,
    email: "my_email@proton.me",
    termsOfServiceAgreed: true,
    createDnsTxtRecord: createDnsTxtRecord,
    removeDnsTxtRecord: removeDnsTxtRecord,
  );

  // Save certificates to a file
  var dir = Directory.systemTemp.path;
  var privatePath = "$dir/private.pem";
  var publicPath = "$dir/public.pem";
  await File("$dir/private.pem").writeAsString(certs.privatePem);
  await File("$dir/public.pem").writeAsString(certs.publicPem);

  // Save ACME account
  var accountPath = "$dir/account.json";
  await File(accountPath).writeAsString(jsonEncode(certs.account.toJson()));

  // Start Authenticated Server
  final context = SecurityContext()
    ..useCertificateChain(publicPath)
    ..usePrivateKey(privatePath);

  // Start the secure server
  var server = await HttpServer.bindSecure(
    InternetAddress.anyIPv4,
    443,
    context,
  );

  // A few months later .....

  // Close Server
  await server.close();

  // Load account from disk
  var account =
      AcmeAccount.fromJson(jsonDecode(File(accountPath).readAsStringSync()));

  // Renew Certificates
  // ignore: unused_local_variable
  var newCerts = await acmeDns01Challenge(
      hosts: hosts,
      createDnsTxtRecord: createDnsTxtRecord,
      removeDnsTxtRecord: removeDnsTxtRecord,
      account: account);

  /// Save [newCerts] and restarts server
  /// no need to re-save the account as this will not change
}
