var secureRandom = require('secure-random');
var AESjs = require('aes-js');
var NodeRSA = require('node-rsa');
var Base64 = require('js-base64').Base64;
var request = require('request');

var payload = "LAG!!!";
console.log('Payload: ' + payload);

var aesKey = secureRandom(256 / 8); // 256 bits
var aesCtr = new AESjs.ModeOfOperation.ctr(aesKey, new AESjs.Counter(5));

console.log('AES Key: ' + aesKey);
console.log('AES Size: ' + aesKey.length);

var bytes = AESjs.util.convertStringToBytes(payload);
var encryptedPayloadb64 = Base64.encode(AESjs.util.convertBytesToString(aesCtr.encrypt(bytes)));
console.log('AES Encrypted Payload(b64): ' + encryptedPayloadb64);

function OnPublicKeyReceived(pkey) {
    var rsaKey = new NodeRSA(pkey);

    console.log("RSA Key:\n" + pkey);
    console.log('Size: ' + rsaKey.getKeySize() + ' bits');
    console.log('MaxDataSize: ' + rsaKey.getMaxMessageSize() + ' bytes');
    console.log("RSA Key IsPublic: " + rsaKey.isPublic());
    console.log("RSA Key IsPrivate: " + rsaKey.isPrivate());
    var rsaEncryptedAesKey = rsaKey.encrypt(aesKey, 'base64');
    console.log('RSA encrypted AES key(b64): ' + rsaEncryptedAesKey);

    request.post('http://localhost:3000/data',
    {
        json: { key: rsaEncryptedAesKey, data: encryptedPayloadb64}
    },
    function (err, response, body) {
        if (err)
            return console.log('Error: ' + err);

        console.log(body)
    });
}

request.get('http://localhost:3000/pkey', function (err, response, body) {
    if (err)
        return console.log('Error: ' + err);

    // Data reception is done, do whatever with it!
    var parsed = JSON.parse(body);

    return OnPublicKeyReceived(parsed['pkey']);
});
