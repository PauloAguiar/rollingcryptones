const async = require('async');
const request = require('request');
const readline = require('readline');
const crypto = require('./crypto');

const input = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

async.whilst(() => true, function(done) {
    var cryptoClient = crypto.Client.generate(256);
    var payload = "";

    async.waterfall([
        (next) => input.question("Insert payload: ", (ans) => next(null, ans)),
        (read, next) => {
            payload = read;
            request.get('http://localhost:3000/pkey', function (err, response, body) {
                if (err) return next(err);
                try {
                    const parsed = JSON.parse(body);
                    next(null, parsed['pkey']);
                } catch (ex) {
                    next(ex);
                }
            });
        },
        function (pkey, next) {
            const rsaEncryptedAesKey = cryptoClient.encryptedKey(pkey);

            request.post('http://localhost:3000/data',
            {
                json: {
                    key: rsaEncryptedAesKey,
                    data: cryptoClient.encrypt(payload)
                }
            },
            function (err, response, body) {
                console.log("Server response:", body)
                next(err, body)
            });
        },
        (response, next) => {
            console.log("Decrypted server response:", cryptoClient.decrypt(response.data));
            next();
        }
    ], function (err) {
        if (err) {
            console.log("Error: " + err);
        }
        done();
    });
});
