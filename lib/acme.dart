import 'dart:async' show FutureOr;
import 'dart:convert'
    show
        LineSplitter,
        base64Decode,
        base64UrlEncode,
        json,
        jsonDecode,
        jsonEncode,
        utf8;
import 'dart:io' show HttpClient, HttpClientResponse;
import 'dart:typed_data' show Uint8List;
import 'package:basic_utils/basic_utils.dart'
    show
        AsymmetricKeyPair,
        CryptoUtils,
        DnsUtils,
        RRecordType,
        RSAPrivateKey,
        RSAPublicKey,
        X509Utils;
import 'package:crypto/crypto.dart' show sha256;

/// Generate an new RSA key pair
AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateRSAKeyPair() {
  var pair = CryptoUtils.generateRSAKeyPair();
  return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
      pair.publicKey as RSAPublicKey, pair.privateKey as RSAPrivateKey);
}

/// Generates a certificate signing request. [commonName] should be your host e.g., "msite.com" "subdomain.mysite.com", or
/// "*.mysite.com" for wildcard certificates.  You should generally
/// create a new key pair for each new csr which can be done with the static method [AcmeUtils.generateKeyPair]
String generateCsr({
  required List<String> hosts,
  required AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> keys,
}) {
  // Define the distinguished name
  final dn = {
    'CN': hosts.first,
  };

  List<String>? san;

  if (hosts.length > 1) {
    san = hosts.skip(1).toList();
  }

  // Generate the CSR
  final csr = X509Utils.generateRsaCsrPem(
    dn,
    keys.privateKey,
    keys.publicKey,
    san: san,
  );

  return csr;
}

/// Creates certificates using th DNS-01 challenge.  
///
/// [hosts] one or more hosts that the certificate will cover.  Note that the first
/// subdomain for any host may be an \* to generate a wildcard certificate.  e.g. ["mysite.org", "deeply.nested.subdomain.at.mysite.org", "*.api.mysite.org", "mysite.com"]
///
/// [createDnsTxtRecord] and [removeDnsRecord] are functions that you supply to
/// crate and remove TXT records from your DNS server.   It could be
/// as simple a printing the value to stdout and waiting for a user to
// manually add the record, or more likely an API call to your DNS provider
/// see [example/main.dart] and [example/cloud_flare.dart] for and example.
/// Note that the value returned by [createDnsTxtRecord]
/// will be passed to [removeDnsRecord] and is likely to be a record identifier. However
/// the value may be null or any other object as needed.
///
/// You must supply either an [account] or alternatively [email] and [termsOfServiceAgreed] accepted.
/// If you supply an  [email] and [termsOfServiceAgreed] a new account will be created.  You
/// must read and agree to the [terms of service](https://www.acmecupsusa.com/pages/terms-of-service#:~:text=The%20service%20and%20all%20products,implied%20warranties%20or%20conditions%20of)
///
/// [directoryUrl] is the base url for the acme endpoint.  If you are using lets encrypt it will be the constant [letsEncryptDirectoryUrl]. You can use [letsEncryptStagingDirectoryUrl] for
/// testing and development.
///
/// [maxDnsLookupRetrys] controls how many times to look for the challenge dns records (after they are created) before failing with an exception.  DNS records are polled every 5 seconds
/// so this will fail after approx 2 minutes.   Adjust longer or shorter as needed.
///
/// [maxDnsLookupRetrys] controls how many times to poll the acme server after a successfully creating a challenge record before failing with an exception. The ACME server is polled every 5 seconds
/// so this will fail after approx 2 minutes.   Adjust longer or shorter as needed.
///
/// [log] a to record human readable progress updates.   By default logs are printed to stdout.  Supply a function to discard or store as needed
Future<AcmeChallengeResult> acmeDns01Challenge(
    {required List<String> hosts,
    required Future<dynamic> Function(String name, String value)
        createDnsTxtRecord,
    required Future<void> Function(dynamic) removeDnsRecord,
    String? email,
    bool termsOfServiceAgreed = false,
    AcmeAccount? account,
    int maxDnsLookupRetrys = 24,
    int maxAcmeCheckRetrys = 24,
    String directoryUrl = letsEncryptDirectoryUrl,
    void Function(String) log = print}) {
  return _withCleanup((defer) async {
    if (account == null && (email == null || !termsOfServiceAgreed)) {
      throw Exception(
          "dns01Challenge - must provide either an account or both an email and a true value for termsOfServiceAgreed");
    }

    var client = await AcmeClient.create(directoryUrl);
    defer(client.close);

    if (account == null) {
      log("creating new account");
      account = await client.newAccount(
          email: email!, termsOfServiceAgreed: termsOfServiceAgreed);
    }

    log("creating new order");
    var order = await client.newOrder(account!, hosts);

    var actions = <Future<void>>[];
    for (var authorizationUrl in order.authorizations) {
      actions.add(_doDnsChallenge(
          client: client,
          account: account!,
          authorizationUrl: authorizationUrl,
          log: log,
          removeDnsRecord: removeDnsRecord,
          createDnsTxtRecord: createDnsTxtRecord,
          maxDnsLookupRetrys: maxDnsLookupRetrys,
          maxAcmeCheckRetrys: maxAcmeCheckRetrys));
    }
    await Future.wait(actions);

    log("completed all challenges");

    log("finalizing");
    var keys = generateRSAKeyPair();
    var csr = generateCsr(hosts: hosts, keys: keys);
    var validOrder = await client.finalize(account!, order, csr);

    log("getting certificate");
    var publicPem = await client.certificate(account!, validOrder);
    var privatePem = CryptoUtils.encodeRSAPrivateKeyToPem(keys.privateKey);
    log("success");
    return AcmeChallengeResult(
        account: account!, privatePem: privatePem, publicPem: publicPem);
  });
}

Future<void> _doDnsChallenge(
    {required AcmeClient client,
    required AcmeAccount account,
    required String authorizationUrl,
    required void Function(String) log,
    required Future<void> Function(dynamic)? removeDnsRecord,
    required Future<dynamic> Function(String name, String value)
        createDnsTxtRecord,
    required int maxDnsLookupRetrys,
    required int maxAcmeCheckRetrys}) async {
  return _withCleanup((defer) async {
    var authorization = await client.authorization(account, authorizationUrl);

    var prefix = authorization.identifier.value;
    log("$prefix - starting dns challenge");
    var host = authorization.identifier.value;
    var challenge =
        authorization.challenges.singleWhere((e) => e.type == "dns-01");
    var challengeRecord = await client.dnsRecord(account, challenge, host);

    log("$prefix - creating public DNS TXT record ${challengeRecord.name}");
    var recordInfo =
        await createDnsTxtRecord(challengeRecord.name, challengeRecord.value);
    defer(() async {
      log("$prefix - removing DNS record");
      var fn = removeDnsRecord;
      if (fn != null) {
        await fn(recordInfo);
      }
    });

    log("$prefix - polling public DNS TXT record");
    var i = 0;
    while (true) {
      var records =
          await DnsUtils.lookupRecord(challengeRecord.name, RRecordType.TXT);
      if (records != null &&
          records.any((e) => e.data == challengeRecord.value)) {
        log("$prefix - public DNS TXT record found");
        break;
      }
      i += 1;
      if (i == maxDnsLookupRetrys) {
        throw Exception(
            "$prefix - did not find public DNS record in $maxDnsLookupRetrys tries, aborting");
      }
      log("$prefix - did not find DNS record on try $i of $maxDnsLookupRetrys, trying again in 5 seconds");
      await Future.delayed(Duration(seconds: 5));
    }

    log("$prefix - completing challenge");
    await client.challengeComplete(account, challenge);

    AcmeStatus status;
    i = 0;
    while (true) {
      status = (await client.challengeCheck(account, challenge)).status;
      if (status == AcmeStatus.valid) {
        log("$prefix - completed challenge");
        break;
      } else if (status == AcmeStatus.pending) {
        i += 1;
        if (i == maxAcmeCheckRetrys) {
          throw Exception(
              "$prefix - challenge status pending after $maxAcmeCheckRetrys tries, aborting");
        }
        log("$prefix - dchallenge status pending on try $i of $maxAcmeCheckRetrys, trying again in 5 seconds");
        await Future.delayed(Duration(seconds: 5));
      } else {
        break;
      }
    }
  });
}

/// The public directory url for Let's Encrypt
const letsEncryptDirectoryUrl =
    "https://acme-v02.api.letsencrypt.org/directory";

/// The public directory url for Let's Encrypt staging.  Used for testing
const letsEncryptStagingDirectoryUrl =
    "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Data object containing certificates and Acme account.  This is the result of a successfull
/// call to [acmeDns01Challenge]
class AcmeChallengeResult {
  AcmeChallengeResult(
      {required this.account,
      required this.privatePem,
      required this.publicPem});
  AcmeAccount account;
  String privatePem;
  String publicPem;
}

/// Makes signed http requests to the ACME server.  Can be used instead of [acmeDns01Challenge] for more
/// control if needed.
class AcmeClient {
  final String directoryUrl;
  String newNonceUrl;
  String newOrderUrl;
  String keyChangeUrl;
  String newAccountUrl;
  HttpClient client;

  void close() {
    client.close();
  }

  AcmeClient(
      {required this.directoryUrl,
      required this.newNonceUrl,
      required this.newAccountUrl,
      required this.keyChangeUrl,
      required this.newOrderUrl,
      required this.client});

  static Future<AcmeClient> createLetsEncryptStaging() =>
      create(letsEncryptStagingDirectoryUrl);
  static Future<AcmeClient> createLetsEncrypt() =>
      create(letsEncryptDirectoryUrl);

  /// Creates an AcmeClient from the supplied [directoryUrl].  Typical values for [directoryUrl] are [letsEncryptDirectoryUrl] and [letsEncryptStagingDirectoryUrl]
  static Future<AcmeClient> create(String directoryUrl) async {
    var client = HttpClient();
    try {
      final request = await client.getUrl(Uri.parse(directoryUrl));
      final response = await request.close();
      var body = await _readBodyAsString(response);

      final directory = json.decode(body);
      final newNonceUrl = directory['newNonce'];
      final newOrderUrl = directory['newOrder'];
      final keyChangeUrl = directory['keyChange'];
      final newAccountUrl = directory['newAccount'];

      return AcmeClient(
          directoryUrl: directoryUrl,
          newNonceUrl: newNonceUrl,
          newAccountUrl: newAccountUrl,
          keyChangeUrl: keyChangeUrl,
          newOrderUrl: newOrderUrl,
          client: client);
    } catch (e) {
      client.close();
      rethrow;
    }
  }

  /// Request a newAccount from the ACME server.
  Future<AcmeAccount> newAccount(
      {required String email, required bool termsOfServiceAgreed}) async {
    final payload = {
      "termsOfServiceAgreed": termsOfServiceAgreed,
      "contact": ["mailto:$email"]
    };

    final keys = generateRSAKeyPair();
    final response =
        await _signedRequest(newAccountUrl, payload, null, keys: keys);
    var body = await _readBodyAsString(response);
    final locationUrl = response.headers['location']!.single;

    var account = AcmeAccount._fromJsonEtc(jsonDecode(body), locationUrl, keys);
    return account;
  }

  /// Request a newOrder from the ACME server.
  Future<AcmeOrder> newOrder(AcmeAccount account, List<String> hosts) async {
    final payload = {
      "identifiers":
          hosts.map((domain) => {"type": "dns", "value": domain}).toList()
    };
    final response = await _signedRequest(newOrderUrl, payload, account);
    var body = await _readBodyAsString(response);
    return AcmeOrder.fromJson(json.decode(body));
  }

  /// Request a new authroization from the ACME server.
  /// The [authotorizationUrl] is from [AcmeOrder.authorizations] see [newOrder]
  Future<AcmeAuthorization> authorization(
      AcmeAccount account, String authorizationUrl) async {
    final response = await _signedRequest(authorizationUrl, null, account);
    var body = await _readBodyAsString(response);
    return AcmeAuthorization.fromJson(jsonDecode(body));
  }

  /// Request a certificate from the ACME server.  This can be done after calling [finalize] on an order.  This will always fail in a staging environment.
  Future<String> certificate(AcmeAccount account, AcmeOrder order) async {
    if (order.certificate == null) {
      throw Exception(
          "Cannot get a certificate on a non-valid order.  This is likely because you are in the staging rather than production environment.  Try creating the AcmeClient with createLetsEncryptClient instead of createLetsEncryptStagingClient.");
    }
    final response = await _signedRequest(order.certificate!, null, account);
    var body = await _readBodyAsString(response);
    return body;
  }

  /// Notify the ACME server that the challenge has been completed and is ready to be checked.  (e.g. the appropriate DNS record is set).
  Future<AcmeChallenge> challengeComplete(
      AcmeAccount account, AcmeChallenge challenge) async {
    final response =
        await _signedRequest(challenge.url, <String, dynamic>{}, account);
    var body = await _readBodyAsString(response);
    return AcmeChallenge.fromJson(jsonDecode(body));
  }

  /// Poll the ACME server on the status of a challenge.  Challenges typically take upto a about one minute to become valid after
  /// calling [challengeComplete].  Clients typically poll the ACME server periodically utill the returned object has a status of [AcmeStatus.valid]
  Future<AcmeChallenge> challengeCheck(
      AcmeAccount account, AcmeChallenge challenge) async {
    final response = await _signedRequest(challenge.url, null, account);
    var body = await _readBodyAsString(response);
    return AcmeChallenge.fromJson(jsonDecode(body));
  }

  /// HTTP request to finalizes an order.  CsrPem is the Certificate Signing Request in PEM format.  The static method
  /// [generateCsr] can be used to generate a new propertly formatted csr.
  Future<AcmeOrder> finalize(
      AcmeAccount account, AcmeOrder order, String csrPem) async {
    final csr = pemToDer(csrPem);
    final payload = {"csr": _base64Bytes(csr)};
    var response = await _signedRequest(order.finalize, payload, account,
        contentType: 'application/pem-csr');
    var body = await _readBodyAsString(response);
    return AcmeOrder.fromJson(jsonDecode(body));
  }

  /// Generates the DnsRecord needed to complete a DNS-01 challenge.
  /// This needs to get updloaded as a TXT record on your DNS provider to pass the DNS challenge
  Future<AcmeDnsRecord> dnsRecord(
      AcmeAccount account, AcmeChallenge dns, String host) async {
    var parts = host.split(".");
    if (parts.first == "*") {
      parts.removeAt(0);
    }

    var host2 = parts.join(".");
    var name = "_acme-challenge.$host2";

    final thumbprint = _thumbprint(account.key);
    final token = dns.token;
    final rawChallengeResponse = "$token.$thumbprint";
    var content =
        _base64Bytes(sha256.convert(utf8.encode(rawChallengeResponse)).bytes);
    return AcmeDnsRecord(name, content);
  }

  Future<HttpClientResponse> _signedRequest(
      String url, Map<String, dynamic>? payload, AcmeAccount? account,
      {AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>? keys,
      String contentType = 'application/jose+json'}) async {
    assert(account != null || keys != null);
    final locationUrl = account?.locationUrl;

    final nonce = await _getNonce();
    final protectedHeader = {
      "alg": "RS256",
      "nonce": nonce,
      "url": url,
      if (locationUrl != null)
        "kid": locationUrl
      else
        "jwk": await _getJwk(keys!.publicKey)
    };

    final protected64 = _base64Json(protectedHeader);
    final payload64 = payload != null ? _base64Json(payload) : "";
    var privateKey = (account?.keys ?? keys!).privateKey;
    final signature = _sign(privateKey, '$protected64.$payload64');
    final body = {
      "protected": protected64,
      "payload": payload64,
      "signature": signature
    };
    final request = await client.postUrl(
      Uri.parse(url),
    );
    request.headers.add("Content-Type", "application/jose+json");
    request.add(utf8.encode(jsonEncode(body)));
    var response = await request.close();
    return response;
  }

  Future<Map<String, dynamic>> _getJwk(RSAPublicKey publicKey) async {
    publicKey = publicKey;
    final n = _base64Bytes(_bigIntToBytes(publicKey.modulus!));
    final e = _base64Bytes(_bigIntToBytes(publicKey.exponent!));

    return {
      "kty": "RSA",
      "n": n, // Remove padding
      "e": e, // Remove padding
    };
  }

  Uint8List _bigIntToBytes(BigInt value) {
    // Convert BigInt to bytes
    var bytes = value.toRadixString(16);
    if (bytes.length % 2 != 0) {
      bytes = '0$bytes';
    }
    return Uint8List.fromList(
      List<int>.generate(
        bytes.length ~/ 2,
        (i) => int.parse(bytes.substring(i * 2, i * 2 + 2), radix: 16),
      ),
    );
  }

  String _sign(RSAPrivateKey privateKey, String data) {
    return _base64Bytes(CryptoUtils.rsaSign(privateKey, utf8.encode(data)));
  }

  static String _base64String(String string) {
    return _base64Bytes(utf8.encode(string));
  }

  static String _base64Bytes(List<int> bytes) {
    return base64UrlEncode(bytes).replaceAll("=", "");
  }

  static String _base64Json(Map<String, Object?> json) {
    return _base64String(jsonEncode(json));
  }

  Future<String> _getNonce() async {
    final response =
        await (await client.headUrl(Uri.parse(newNonceUrl))).close();
    if (response.statusCode != 200 && response.statusCode != 204) {
      throw Exception('Failed to get nonce');
    }
    final nonce = response.headers['replay-nonce'];
    if (nonce == null) {
      throw Exception('Nonce not found in response headers');
    }
    return nonce.single;
  }

  static String _thumbprint(AcmeJwk jwk) {
    /// Note that ACME protocl requires the jwk keys to be sorted in the
    /// json string representation. This is, annoyingly,
    /// against the json standard, but this will definitly fail if the keys
    /// encoded in the wrong order.
    /// See: https://www.rfc-editor.org/rfc/rfc7638 example 3.1 for details
    return _base64Bytes(
        sha256.convert(utf8.encode(_sortedJsonEncode(jwk.toJson()))).bytes);
  }

  static String _sortedJsonEncode(Map<String, dynamic> data) {
    var sortedKeys = data.keys.toList()..sort();
    var sortedMap = {for (var k in sortedKeys) k: data[k]};
    return jsonEncode(sortedMap);
  }

  static Uint8List pemToDer(String pem) {
    final base64String = LineSplitter()
        .convert(pem)
        .where((line) => !line.startsWith('-----'))
        .join('');
    return base64Decode(base64String);
  }
}

Future<String> _readBodyAsString(HttpClientResponse request) {
  return request.transform(utf8.decoder).join();
}

/// Acme data transfer object
class AcmeOrder {
  final String status;
  final DateTime expires;
  final List<AcmeIdentifier> identifiers;
  final List<String> authorizations;
  final String finalize;
  final String? certificate;

  AcmeOrder({
    required this.status,
    required this.expires,
    required this.identifiers,
    required this.authorizations,
    required this.finalize,
    required this.certificate,
  });

  factory AcmeOrder.fromJson(Map<String, dynamic> json) {
    return AcmeOrder(
      status: json['status'],
      expires: DateTime.parse(json['expires']),
      identifiers: (json['identifiers'] as List)
          .map((i) => AcmeIdentifier.fromJson(i))
          .toList(),
      authorizations: List<String>.from(json['authorizations']),
      finalize: json['finalize'],
      certificate: json['certificate'],
    );
  }
}

/// Acme data transfer object
class AcmeIdentifier {
  final String type;
  final String value;

  AcmeIdentifier({
    required this.type,
    required this.value,
  });

  factory AcmeIdentifier.fromJson(Map<String, dynamic> json) {
    return AcmeIdentifier(
      type: json['type'],
      value: json['value'],
    );
  }
}

/// Acme data transfer object
class AcmeAuthorization {
  final AcmeIdentifier identifier;
  final String status;
  final DateTime expires;
  final List<AcmeChallenge> challenges;

  AcmeAuthorization({
    required this.identifier,
    required this.status,
    required this.expires,
    required this.challenges,
  });

  factory AcmeAuthorization.fromJson(Map<String, dynamic> json) {
    return AcmeAuthorization(
      identifier: AcmeIdentifier.fromJson(json['identifier']),
      status: json['status'],
      expires: DateTime.parse(json['expires']),
      challenges: (json['challenges'] as List)
          .map((c) => AcmeChallenge.fromJson(c))
          .toList(),
    );
  }
}

/// Acme data transfer object
enum AcmeStatus {
  pending,
  valid,
  invalid,
  deactivated,
  expired,
  revoked,
}

/// Acme data transfer object
class AcmeChallenge {
  final String type;
  final AcmeStatus status;
  final String url;
  final String token;

  AcmeChallenge({
    required this.type,
    required this.status,
    required this.url,
    required this.token,
  });

  factory AcmeChallenge.fromJson(Map<String, dynamic> json) {
    return AcmeChallenge(
      type: json['type'],
      status: _acmeStatusFromString(json['status']),
      url: json['url'],
      token: json['token'],
    );
  }
}

AcmeStatus _acmeStatusFromString(String status) {
  switch (status) {
    case 'pending':
      return AcmeStatus.pending;
    case 'valid':
      return AcmeStatus.valid;
    case 'invalid':
      return AcmeStatus.invalid;
    case 'deactivated':
      return AcmeStatus.deactivated;
    case 'expired':
      return AcmeStatus.expired;
    case 'revoked':
      return AcmeStatus.revoked;
    default:
      throw ArgumentError('Unknown status: $status');
  }
}

/// An Acme account.  Accounts can be saved for re-use later using [toJson] method and [fromJson] constructor respectively.
class AcmeAccount {
  final AcmeJwk key;
  final List<String> contact;
  final String initialIp;
  final DateTime createdAt;
  final AcmeStatus status;
  final String locationUrl;
  final AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> keys;

  AcmeAccount({
    required this.key,
    required this.contact,
    required this.initialIp,
    required this.createdAt,
    required this.status,
    required this.locationUrl,
    required this.keys,
  });

  factory AcmeAccount._fromJsonEtc(Map<String, dynamic> json,
      String locationUrl, AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> keys) {
    return AcmeAccount(
      key: AcmeJwk.fromJson(json['key']),
      contact: List<String>.from(json['contact']),
      initialIp: json['initialIp'],
      createdAt: DateTime.parse(json['createdAt']),
      status: _acmeStatusFromString(json['status']),
      keys: keys,
      locationUrl: locationUrl,
    );
  }

  factory AcmeAccount.fromJson(Map<String, dynamic> json) {
    return AcmeAccount(
      key: AcmeJwk.fromJson(json['key']),
      contact: List<String>.from(json['contact']),
      initialIp: json['initialIp'],
      createdAt: DateTime.parse(json['createdAt']),
      status: AcmeStatus.values
          .firstWhere((e) => e.toString() == 'AcmeStatus.${json['status']}'),
      locationUrl: json['locationUrl'],
      keys: AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
        CryptoUtils.rsaPublicKeyFromPem(json['publicKeyPem']),
        CryptoUtils.rsaPrivateKeyFromPem(json['privateKeyPem']),
      ),
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'key': key.toJson(),
      'contact': contact,
      'initialIp': initialIp,
      'createdAt': createdAt.toIso8601String(),
      'status': status.toString().split('.').last,
      'locationUrl': locationUrl,
      'publicKeyPem': CryptoUtils.encodeRSAPublicKeyToPem(keys.publicKey),
      'privateKeyPem': CryptoUtils.encodeRSAPrivateKeyToPem(keys.privateKey),
    };
  }
}

/// Acme data transfer object
class AcmeJwk {
  final String kty;
  final String n;
  final String e;

  AcmeJwk({
    required this.kty,
    required this.n,
    required this.e,
  });

  Map<String, Object?> toJson() => {"kty": kty, "n": n, "e": e};

  factory AcmeJwk.fromJson(Map<String, dynamic> json) {
    return AcmeJwk(
      kty: json['kty'],
      n: json['n'],
      e: json['e'],
    );
  }
}

/// Data object that stores the name and value of a DNS TXT record.  Used for DNS-01 challenges
class AcmeDnsRecord {
  AcmeDnsRecord(this.name, this.value);

  /// The name for the txt record.  e.g. _acme-challenge.my-subdomain.example.com
  final String name;

  /// The value (sometimes called data) for the TXT record
  final String value;
}

/// Inspired by GOLang defer blocks
/// ```
///  // Example Useage
///  await withCleanup((defer) async {
///    var x = await File("foo").open();
///    defer(x.close);
///
///     // Use file here
///  });
/// ```
Future<T> _withCleanup<T>(
    Future<T> Function(void Function(FutureOr<void> Function()) defer)
        fn) async {
  final cleanupList = <FutureOr<void> Function()>[];
  void deferInternal(FutureOr<void> Function() cleanup) {
    cleanupList.add(cleanup);
  }

  try {
    return await fn(deferInternal);
  } finally {
    for (var action in cleanupList.reversed) {
      await action();
    }
  }
}
