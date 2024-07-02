

import 'dart:convert';
import 'dart:io';
import 'package:acme/acme.dart';
import 'cloud_flare.dart';

void main() async {
  
  // Create a certificate for one or more hosts
  var hosts = ["mysite.org", "deeply.nested.subdomain.at.mysite.org", "*.api.mysite.org", "mysite.com"];

  // Create the certificate using DNS-01 challenge
  var certs = await acmeDns01Challenge(
    hosts: hosts, 
    createDnsTxtRecord:createDnsTxtRecord, 
    removeDnsRecord: removeDnsRecord,
    email: "my_email@proton.me",
    termsOfServiceAgreed: true,
    directoryUrl: letsEncryptStagingDirectoryUrl
  );

  // Save certificates to a file
  var dir  = Directory.systemTemp.path;
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
  var account = AcmeAccount.fromJson(jsonDecode(File(accountPath).readAsStringSync()));

  // Renew Certificates
  // ignore: unused_local_variable
  var newCerts = await acmeDns01Challenge(hosts: hosts, 
    createDnsTxtRecord:createDnsTxtRecord, 
    removeDnsRecord: removeDnsRecord,
    account: account
  );

  /// Save [newCerts] and restarts server
  /// no need to re-save the account as this will not change

}


Future<dynamic> createDnsTxtRecord(String name, String value) {
  // You will need to implement a function that adds a 
  // TXT record on your dns server with the given name and value
  // this will be different depending on your dns provider.  It could be 
  // as simple a printing the value to stdout and waiting for a user to
  // manually add the record, or more likely an API call to your DNS provider
  // as shown below.  Note that the value returned by this function 
  // will be passed to removeDnsRecord when the record is no longer needed
  return cloudFlareClient.dnsRecordCreate("TXT", name, value);
}

Future<void> removeDnsRecord(dynamic record) {
  // You will need to implement a function that removes the
  // TXT record on your dns server
  return cloudFlareClient.dnsRecordDelete(record.id);
}

CloudFlareClient get cloudFlareClient {
  var parts = File("keys/cloue_flare_keys.txt").readAsStringSync().split(".");
  var apiKey = parts[0];
  var zoneId = parts[1];
  return CloudFlareClient(domain: "shine.icu", zoneId: zoneId, apiKey: apiKey);
}