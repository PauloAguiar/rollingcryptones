var async = require('async');
var secureRandom = require('secure-random');
var AESjs = require('aes-js');
var NodeRSA = require('node-rsa');
var request = require('request');
var readline = require('readline');

const input = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

async.whilst(() => true, function() {
    var aesKey = secureRandom(256 / 8); // 256 bits

    console.log('AES Key: ' + aesKey);
    console.log('AES Size: ' + aesKey.length);

    async.waterfall([
        (next) => input.question("Insert payload: ", (ans) => next(null, ans)),
        (payload, next) => {
            var encrypter = new AESjs.ModeOfOperation.ctr(aesKey, new AESjs.Counter(5));
            var bytes = AESjs.util.convertStringToBytes(payload);
            var encryptedBytes = encrypter.encrypt(bytes);
            console.log('AES Encrypted Payload(bytes): ', encryptedBytes)

            var encryptedPayloadb64 = encryptedBytes.toString('base64');
            console.log('AES Encrypted Payload(b64): ' + encryptedPayloadb64);

            request.get('http://localhost:3000/pkey', function (err, response, body) {
                if (err) return next(err);
                try {
                    var parsed = JSON.parse(body);
                    next(null, parsed['pkey'], aesKey, encryptedPayloadb64);
                } catch (ex) {
                    next(ex);
                }
            });
        },
        function (pkey, aesKey, encryptedPayload, next) {
            var rsaKey = new NodeRSA(pkey);

            console.log("RSA Key:\n" + pkey);
            console.log('Size: ' + rsaKey.getKeySize() + ' bits');
            console.log('MaxDataSize: ' + rsaKey.getMaxMessageSize() + ' bytes');
            console.log("RSA Key IsPublic: " + rsaKey.isPublic());
            console.log("RSA Key IsPrivate: " + rsaKey.isPrivate());
            var rsaEncryptedAesKey = rsaKey.encrypt(new Buffer(aesKey), 'base64');
            console.log('RSA encrypted AES key(b64): ' + rsaEncryptedAesKey);

            request.post('http://localhost:3000/data',
            {
                json: { key: rsaEncryptedAesKey, data: encryptedPayload}
            },
            function (err, response, body) {
                console.log("Server response:", body)
                next(err, body)
            });
        },
        (response, next) => {
            var decrypter = new AESjs.ModeOfOperation.ctr(aesKey, new AESjs.Counter(5));
            var dataBytes = new Buffer(response.data, 'base64');
            var decrypted = decrypter.decrypt(dataBytes).toString('utf8');
            console.log("Decrypted server response:", decrypted);
            next();
        }
    ], function (err) {
        if (err) {
            console.log("Error: " + err);
        }
    });
});
