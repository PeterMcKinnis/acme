import "dart:convert";
import "dart:io";

class CloudFlareClient {
  CloudFlareClient(
      {required this.domain, required this.zoneId, required this.apiKey});

  String domain;
  String zoneId;
  String apiKey;

  Future<TxtRecord> dnsRecordCreate(String type, String name, String content,
      {int ttl = 60, bool proxied = false}) async {
    final body = jsonEncode({
      "type": type,
      "name": name,
      "content": content,
      "ttl": ttl,
      "proxied": proxied
    });

    var json = await _fetch("POST", "dns_records", body: body);
    return TxtRecord.fromJson(json["result"]);
  }

  Future<void> dnsRecordDelete(String dnsRecordId) async {
    await _fetch("DELETE", "dns_records/$dnsRecordId");
  }

  Future<List<TxtRecord>> txtRecordList() async {
    var json = await _fetch("GET", "dns_records?type=TXT");
    final result = (json["result"] as List<Object?>)
        .map((e) => TxtRecord.fromJson(e as Map<String, Object?>))
        .toList();
    return result;
  }

  Future<Map<String, dynamic>> _fetch(String method, String path,
      {String? body}) async {
    final headers = {
      "Authorization": "Bearer $apiKey",
      "Content-Type": "application/json"
    };

    var uri =
        Uri.parse("https://api.cloudflare.com/client/v4/zones/$zoneId/$path");
    var client = HttpClient();
    try {
      var request = await client.openUrl(method, uri);
      for (var header in headers.entries) {
        request.headers.add(header.key, header.value);
      }
      if (body != null) {
        request.add(utf8.encode(body));
      }
      var response = await request.close();
      var content = await response.transform(utf8.decoder).join();

      var statusCode = response.statusCode;
      if (statusCode < 200 || statusCode >= 300) {
        throw Exception(
            "cloudflare request failed with status code ${response.statusCode}\n$body");
      }
      return jsonDecode(content);
    } finally {
      client.close();
    }
  }
}

class TxtRecord {
  final String content;
  final String name;
  final String type;
  final String? comment;
  final DateTime createdOn;
  final String id;
  final bool locked;
  final Meta meta;
  final DateTime modifiedOn;
  final bool proxiable;
  final List<String>? tags;
  final int ttl;

  TxtRecord({
    required this.content,
    required this.name,
    required this.type,
    this.comment,
    required this.createdOn,
    required this.id,
    required this.locked,
    required this.meta,
    required this.modifiedOn,
    required this.proxiable,
    this.tags,
    required this.ttl,
  });

  factory TxtRecord.fromJson(Map<String, dynamic> json) {
    return TxtRecord(
      content: json['content'],
      name: json['name'],
      type: json['type'],
      comment: json['comment'],
      createdOn: DateTime.parse(json['created_on']),
      id: json['id'],
      locked: json['locked'],
      meta: Meta.fromJson(json['meta']),
      modifiedOn: DateTime.parse(json['modified_on']),
      proxiable: json['proxiable'],
      tags: json['tags'] != null ? List<String>.from(json['tags']) : null,
      ttl: json['ttl'],
    );
  }
}

class Meta {
  final bool? autoAdded;
  final String? source;

  Meta({
    this.autoAdded,
    this.source,
  });

  factory Meta.fromJson(Map<String, dynamic> json) {
    return Meta(
      autoAdded: json['auto_added'],
      source: json['source'],
    );
  }
}
