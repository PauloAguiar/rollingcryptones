var AESjs = require('aes-js');
var NodeRSA = require('node-rsa');

console.log('AES EXAMPLE');

// 128-bit, 192-bit and 256-bit keys
var key_128 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
var key_192 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
               16, 17, 18, 19, 20, 21, 22, 23];
var key_256 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
               16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
               29, 30, 31];

// or, similarly, with buffers (node.js only):
var key_128 = new Buffer([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
var key_192 = new Buffer([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
               16, 17, 18, 19, 20, 21, 22, 23]);
var key_256 = new Buffer([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
               16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
               29, 30, 31]);

var key = AESjs.util.convertStringToBytes("Example128BitKey");
console.log('Key: ' + key);
console.log('Size: ' + key.length);

// Convert text to bytes
var text = 'Text may be any length you wish, no padding is required.';
console.log('Text: ' + text);

var textBytes = AESjs.util.convertStringToBytes(text);
console.log('TextBytes: ' + Array.apply([], textBytes).join(", "));

// The counter is optional, and if omitted will begin at 0
var aesCtr = new AESjs.ModeOfOperation.ctr(key, new AESjs.Counter(5));
var encryptedBytes = aesCtr.encrypt(textBytes);
console.log('EncryptedBytes: ' + Array.apply([], encryptedBytes).join(", "));

// The counter mode of operation maintains internal state, so to
// decrypt a new instance must be instantiated.
var aesCtr = new AESjs.ModeOfOperation.ctr(key, new AESjs.Counter(5));
var decryptedBytes = aesCtr.decrypt(encryptedBytes);
console.log('DecryptedBytes: ' + Array.apply([], decryptedBytes).join(", "));

// Convert our bytes back into text
var decryptedText = AESjs.util.convertBytesToString(decryptedBytes);
console.log('DecryptedText: ' + decryptedText);
// "Text may be any length you wish, no padding is required."
console.log('END OF AES EXAMPLE\n'); 

console.log('RSA EXAMPLE');

var key = new NodeRSA({b: 1024});

console.log('Size: ' + key.getKeySize() + ' bits');
console.log('MaxDataSize: ' + key.getMaxMessageSize() + ' bytes');

// 'public' or 'pkcs8-public' == 'pkcs8-public-pem' — public key encoded in pcks8 scheme as pem string.
// 'pkcs8-public-der' — public key encoded in pcks8 scheme as binary buffer.
var publicDer = key.exportKey('public');
console.log('Public Key:\n' + publicDer);

// 'private' or 'pkcs1' or 'pkcs1-private' == 'pkcs1-private-pem' — private key encoded in pcks1 scheme as pem string.
// 'pkcs8' or 'pkcs8-private' == 'pkcs8-private-pem' — private key encoded in pcks8 scheme as pem string.
// 'pkcs1-der' == 'pkcs1-private-der' — private key encoded in pcks1 scheme as binary buffer.
var privateDer = key.exportKey('private');
console.log('Private Key:\n' + privateDer);

// key.encrypt(buffer, [encoding], [source_encoding]);
// key.encryptPrivate(buffer, [encoding], [source_encoding]); // use private key for encryption
// buffer — {buffer} — data for encrypting, may be string, Buffer, or any object/array. Arrays and objects will encoded to JSON string first.
// encoding — {string} — encoding for output result, may be 'buffer', 'binary', 'hex' or 'base64'. Default 'buffer'.
// source_encoding — {string} — source encoding, works only with string buffer. Can take standard Node.js Buffer encodings (hex, utf8, base64, etc). 'utf8' by default.

// key.decrypt(buffer, [encoding]);
// key.decryptPublic(buffer, [encoding]); // use public key for decryption
// buffer — {buffer} — data for decrypting. Takes Buffer object or base64 encoded string.
// encoding — {string} — encoding for result string. Can also take 'buffer' for raw Buffer object, or 'json' for automatic JSON.parse result. Default 'buffer'.

// key.sign(buffer, [encoding], [source_encoding]);
// key.verify(buffer, signature, [source_encoding], [signature_encoding])
// buffer — {buffer} — data for check, same as encrypt method.
// signature — {string} — signature for check, result of sign method.
// source_encoding — {string} — same as for encrypt method.
// signature_encoding — {string} — encoding of given signature. May be 'buffer', 'binary', 'hex' or 'base64'. Default 'buffer'.

// http://stackoverflow.com/questions/454048/what-is-the-difference-between-encrypting-and-signing-in-asymmetric-encryption
// When encrypting, you use their public key to write message and they use their private key to read it.
// When signing, you use your private key to write message's signature, and they use your public key to check if it's really yours.

// client generate a random aes key
// use the aes key to encrypt the data you need (rsa take longer time and have length limitation, so better use aes to do encrypt)
// use the public key to encrypt the aes key
// pass the encrypted data and the aes key encrypted by rsa public key to server
// when server receive, decrypt that aes key by private key and then decrypt the attached data by the decrypted aes key


// randomstring.generate({
//   charset: 'abc'
// });
// generate(options)
//       length - the length of the random string. (default: 32) [OPTIONAL]
//       readable - exclude poorly readable chars: 0OIl. (default: false) [OPTIONAL]
//       charset - define the character set for the string. (default: 'alphanumeric') [OPTIONAL]
//             alphanumeric - [0-9 a-z A-Z]
//             alphabetic - [a-z A-Z]
//             numeric - [0-9]
//             hex - [0-9 a-f]
//       custom - any given characters
//       capitalization - define whether the output should be lowercase / uppercase only. (default: null) [OPTIONAL]
//             lowercase
//             uppercase