var secureRandom = require('secure-random');
var AESjs = require('aes-js');
var NodeRSA = require('node-rsa');

function Server(rsaKeySize) {
  this.rsa = new NodeRSA({b: rsaKeySize});

  console.log('KEY INFO')
  console.log('Size: ' + this.rsa.getKeySize() + ' bits');
  console.log('MaxDataSize: ' + this.rsa.getMaxMessageSize() + ' bytes\n');
}

Server.prototype.publicKey = function() {
  return this.rsa.exportKey('public');
}

Server.prototype.exchange = function(encryptedKey) {
  console.log('clientRSAEncryptedKey', encryptedKey);
  var aesKey = this.rsa.decrypt(encryptedKey, 'buffer', 'base64');

  console.log('clientAESKey', JSON.stringify(aesKey));
  return new Client(aesKey);
}

function Client(aesKey) {
  this.aesKey = new Buffer(aesKey);
  this.encrypter = new AESjs.ModeOfOperation.ctr(aesKey, new AESjs.Counter(5));
  this.decrypter = new AESjs.ModeOfOperation.ctr(aesKey, new AESjs.Counter(5));
}

Client.prototype.encrypt = function(data) {
  var encryptedBytes = this.encrypter.encrypt(new Buffer(data));
  console.log('Encrypt: AES Encrypted Payload(bytes): ', encryptedBytes)

  var encryptedB64 = encryptedBytes.toString('base64');
  console.log('Encrypt: AES Encrypted Payload(b64): ' + encryptedB64);
  return encryptedB64;
}

Client.prototype.decrypt = function(data) {
  var encryptedBytes = new Buffer(data, 'base64');
  console.log('Decrypt: AES Encrypted Payload(bytes): ', encryptedBytes)

  var decryptedData = this.decrypter.decrypt(encryptedBytes).toString('utf8');
  console.log('Decrypt: AES Decrypted Payload(utf8): ', decryptedData)
  return decryptedData;
}

Client.prototype.encryptedKey = function(rsaPubKey) {
  var rsa = new NodeRSA(rsaPubKey);

  console.log("RSA Key:\n" + rsaPubKey);
  console.log('Size: ' + rsa.getKeySize() + ' bits');
  console.log('MaxDataSize: ' + rsa.getMaxMessageSize() + ' bytes');
  console.log("RSA Key IsPublic: " + rsa.isPublic());
  console.log("RSA Key IsPrivate: " + rsa.isPrivate());

  var rsaEncryptedAesKey = rsa.encrypt(this.aesKey, 'base64');
  console.log('RSA encrypted AES key(b64): ' + rsaEncryptedAesKey);
  return rsaEncryptedAesKey;
}

Client.generate = function(aesKeySizeBits) {
    var aesKey = secureRandom(aesKeySizeBits / 8); // bits -> bytes

    console.log('AES Key: ' + aesKey);
    console.log('AES Size: ' + aesKey.length);

    return new Client(aesKey);
}

module.exports = {
  Server: Server,
  Client: Client
}
