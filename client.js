const async = require('async');
const secureRandom = require('secure-random');
const AESjs = require('aes-js');
const NodeRSA = require('node-rsa');
const request = require('request');
const readline = require('readline');

const input = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

async.whilst(() => true, function() {
    const aesKey = secureRandom(256 / 8); // 256 bits

    console.log('AES Key: ' + aesKey);
    console.log('AES Size: ' + aesKey.length);

    async.waterfall([
        (next) => input.question("Insert payload: ", (ans) => next(null, ans)),
        (payload, next) => {
            const encipher = new AESjs.ModeOfOperation.ctr(aesKey, new AESjs.Counter(5));
            const bytes = new Buffer(payload);
            const encryptedBytes = encipher.encrypt(bytes);
            console.log('AES Encrypted Payload(bytes): ', encryptedBytes);

            const encryptedPayloadB64 = encryptedBytes.toString('base64');
            console.log('AES Encrypted Payload(b64): ' + encryptedPayloadB64);

            request.get('http://localhost:3000/pkey', function (err, response, body) {
                if (err) return next(err);
                try {
                    const parsed = JSON.parse(body);
                    next(null, parsed['pkey'], aesKey, encryptedPayloadB64);
                } catch (ex) {
                    next(ex);
                }
            });
        },
        function (pkey, aesKey, encryptedPayload, next) {
            const rsaKey = new NodeRSA(pkey);

            console.log("RSA Key:\n" + pkey);
            console.log('Size: ' + rsaKey.getKeySize() + ' bits');
            console.log('MaxDataSize: ' + rsaKey.getMaxMessageSize() + ' bytes');
            console.log("RSA Key IsPublic: " + rsaKey.isPublic());
            console.log("RSA Key IsPrivate: " + rsaKey.isPrivate());
            const rsaEncryptedAesKey = rsaKey.encrypt(new Buffer(aesKey), 'base64');
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
            const decipher = new AESjs.ModeOfOperation.ctr(aesKey, new AESjs.Counter(5));
            const dataBytes = new Buffer(response.data, 'base64');
            const decrypted = decipher.decrypt(dataBytes).toString('utf8');
            console.log("Decrypted server response:", decrypted);
            next();
        }
    ], function (err) {
        if (err) {
            console.log("Error: " + err);
        }
    });
});
