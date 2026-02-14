import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:matrix/encryption/utils/session_key.dart';
import 'package:matrix/matrix.dart';
import 'package:vodozemac/vodozemac.dart';

const _header = '-----BEGIN MEGOLM SESSION DATA-----';
const _footer = '-----END MEGOLM SESSION DATA-----';
const _version = 0x01;
const _pbkdf2Rounds = 500000;

/// PBKDF2-HMAC-SHA-512 producing [length] bytes (default 64).
/// The `crypto` package provides HMAC + SHA-512; we implement the PBKDF2 loop
/// because vodozemac's CryptoUtils.pbkdf2 is hard-coded to 32 bytes.
Uint8List _pbkdf2Sha512(
  List<int> passphrase,
  List<int> salt,
  int iterations, {
  int length = 64,
}) {
  final hmacFactory = Hmac(sha512, passphrase);
  final blocks = (length + 63) ~/ 64; // SHA-512 output = 64 bytes per block
  final result = BytesBuilder();

  for (var block = 1; block <= blocks; block++) {
    // U1 = PRF(passphrase, salt || INT_32_BE(block))
    final blockBytes = Uint8List(4);
    ByteData.sublistView(blockBytes).setUint32(0, block);
    var u = Uint8List.fromList(
      hmacFactory.convert([...salt, ...blockBytes]).bytes,
    );
    final xored = Uint8List.fromList(u);

    for (var i = 1; i < iterations; i++) {
      u = Uint8List.fromList(hmacFactory.convert(u).bytes);
      for (var j = 0; j < xored.length; j++) {
        xored[j] ^= u[j];
      }
    }

    result.add(xored);
  }

  return Uint8List.fromList(result.toBytes().sublist(0, length));
}

/// Imports Megolm session keys from a file exported by another Matrix client
/// (e.g. Element). The file must use the standard
/// `-----BEGIN MEGOLM SESSION DATA-----` format as defined in the Matrix spec.
///
/// Returns the number of successfully imported sessions.
Future<int> importRoomKeys(
  Client client,
  Uint8List fileBytes,
  String passphrase,
) async {
  final String fileString;
  try {
    fileString = utf8.decode(fileBytes);
  } on FormatException {
    throw Exception('Not a valid key export file');
  }

  // Strip headers and decode base64 payload
  final lines = fileString
      .split('\n')
      .map((l) => l.trim())
      .where((l) => l.isNotEmpty)
      .toList();

  if (lines.isEmpty ||
      lines.first != _header ||
      lines.last != _footer) {
    throw Exception('Not a valid key export file');
  }

  final Uint8List data;
  try {
    final base64Body = lines.sublist(1, lines.length - 1).join('');
    data = base64.decode(base64Body);
  } on FormatException {
    throw Exception('Not a valid key export file');
  }

  // Parse binary header: version(1) + salt(16) + iv(16) + rounds(4) + ... + hmac(32)
  if (data.length < 37 + 32) {
    throw Exception('Not a valid key export file');
  }

  final version = data[0];
  if (version != _version) {
    throw Exception('Unsupported key export version: $version');
  }

  final salt = data.sublist(1, 17);
  final iv = data.sublist(17, 33);
  final rounds =
      ByteData.sublistView(Uint8List.fromList(data.sublist(33, 37)))
          .getUint32(0);

  final ciphertext = data.sublist(37, data.length - 32);
  final hmacStored = data.sublist(data.length - 32);

  // Derive key via PBKDF2-HMAC-SHA-512 -> 64 bytes (first 32 = AES, last 32 = HMAC)
  final derived = _pbkdf2Sha512(
    utf8.encode(passphrase),
    salt,
    rounds,
  );

  final aesKey = derived.sublist(0, 32);
  final hmacKey = derived.sublist(32, 64);

  // Verify HMAC-SHA-256
  final hmacInput = data.sublist(0, data.length - 32);
  final hmacComputed = CryptoUtils.hmac(key: hmacKey, input: hmacInput);

  if (!_constantTimeEquals(hmacComputed, hmacStored)) {
    throw Exception('Wrong passphrase or corrupted file');
  }

  // Decrypt with AES-256-CTR
  final plaintext = CryptoUtils.aesCtr(
    input: ciphertext,
    key: aesKey,
    iv: iv,
  );

  // Parse JSON array of sessions
  final List sessions;
  try {
    sessions = json.decode(utf8.decode(plaintext)) as List;
  } catch (_) {
    throw Exception('Wrong passphrase or corrupted file');
  }

  final keyManager = client.encryption?.keyManager;
  if (keyManager == null) {
    throw Exception('Encryption is not enabled on this client');
  }

  var count = 0;
  for (final session in sessions) {
    final map = session as Map<String, dynamic>;
    final roomId = map['room_id'] as String;
    final sessionId = map['session_id'] as String;
    final senderKey = map['sender_key'] as String;
    final senderClaimedKeys =
        (map['sender_claimed_keys'] as Map<String, dynamic>?)
            ?.cast<String, String>();

    await keyManager.setInboundGroupSession(
      roomId,
      sessionId,
      senderKey,
      map,
      forwarded: true,
      senderClaimedKeys: senderClaimedKeys ?? <String, String>{},
    );
    count++;
  }

  return count;
}

/// Exports all Megolm session keys from the client in the standard
/// `-----BEGIN MEGOLM SESSION DATA-----` format, encrypted with the given
/// passphrase.
///
/// Returns the file contents as bytes.
Future<Uint8List> exportRoomKeys(
  Client client,
  String passphrase,
) async {
  final database = client.database;
  final encryption = client.encryption;
  if (encryption == null) {
    throw Exception('Encryption is not enabled on this client');
  }

  final dbSessions = await database.getAllInboundGroupSessions();
  final pickleKey = client.userID!;

  final sessions = <Map<String, dynamic>>[];
  for (final dbSession in dbSessions) {
    try {
      final sessionKey = SessionKey.fromDb(dbSession, pickleKey);
      if (!sessionKey.isValid) continue;

      sessions.add({
        'algorithm': AlgorithmTypes.megolmV1AesSha2,
        'forwarding_curve25519_key_chain':
            sessionKey.forwardingCurve25519KeyChain,
        'sender_key': sessionKey.senderKey,
        'sender_claimed_keys': sessionKey.senderClaimedKeys,
        'session_key':
            sessionKey.inboundGroupSession!.exportAtFirstKnownIndex(),
        'room_id': sessionKey.roomId,
        'session_id': sessionKey.sessionId,
      });
    } catch (e) {
      Logs().w('Failed to export session ${dbSession.sessionId}', e);
    }
  }

  if (sessions.isEmpty) {
    throw Exception('No session keys to export');
  }

  // Encrypt the JSON payload
  final plaintext = Uint8List.fromList(utf8.encode(json.encode(sessions)));

  final random = Random.secure();
  final salt = Uint8List.fromList(
    List.generate(16, (_) => random.nextInt(256)),
  );
  final iv = Uint8List.fromList(
    List.generate(16, (_) => random.nextInt(256)),
  );

  // Encode rounds as big-endian uint32
  final roundsBytes = Uint8List(4);
  ByteData.sublistView(roundsBytes).setUint32(0, _pbkdf2Rounds);

  // Derive key via PBKDF2-HMAC-SHA-512 -> 64 bytes
  final derived = _pbkdf2Sha512(
    utf8.encode(passphrase),
    salt,
    _pbkdf2Rounds,
  );

  final aesKey = derived.sublist(0, 32);
  final hmacKey = derived.sublist(32, 64);

  // Encrypt with AES-256-CTR
  final ciphertext = CryptoUtils.aesCtr(
    input: plaintext,
    key: aesKey,
    iv: iv,
  );

  // Build the binary payload: version + salt + iv + rounds + ciphertext
  final hmacInput = Uint8List.fromList([
    _version,
    ...salt,
    ...iv,
    ...roundsBytes,
    ...ciphertext,
  ]);

  // Compute HMAC-SHA-256
  final hmac = CryptoUtils.hmac(key: hmacKey, input: hmacInput);

  // Final binary: hmacInput + hmac
  final binaryData = Uint8List.fromList([...hmacInput, ...hmac]);

  // Base64 encode and wrap in headers
  final base64Data = base64.encode(binaryData);

  // Split into 76-character lines per PEM convention
  final wrappedLines = <String>[];
  for (var i = 0; i < base64Data.length; i += 76) {
    final end = i + 76;
    wrappedLines.add(
      base64Data.substring(
        i,
        end > base64Data.length ? base64Data.length : end,
      ),
    );
  }

  final output = '$_header\n${wrappedLines.join('\n')}\n$_footer\n';
  return Uint8List.fromList(utf8.encode(output));
}

bool _constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var result = 0;
  for (var i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result == 0;
}
