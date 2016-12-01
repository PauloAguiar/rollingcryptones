var express = require('express');
var bodyParser = require('body-parser');
var logger = require('morgan');
var AESjs = require('aes-js');
var NodeRSA = require('node-rsa');

// Configure Web Server
var app = express();
app.use(logger('dev'));
app.use(bodyParser.json());

// Set KEY
var key = new NodeRSA({b: 1024});

console.log('KEY INFO');
console.log('Size: ' + key.getKeySize() + ' bits');
console.log('MaxDataSize: ' + key.getMaxMessageSize() + ' bytes\n');

app.set('pkey', key.exportKey('public'));

// Routes
app.get('/pkey', function (req, res) {
  return res.json({'pkey': app.get('pkey')});
});

app.post('/data', function (req, res) {
  const body = req.body;

  const clientRSAEncryptedKey = body.key;
  console.log('clientRSAEncryptedKey', clientRSAEncryptedKey);

  const clientAESEncryptedData = body.data;
  console.log('clientAESEncryptedData', clientAESEncryptedData);

  const clientAESKey = key.decrypt(clientRSAEncryptedKey, 'buffer', 'base64').toJSON().data;
  console.log('clientAESKey', JSON.stringify(clientAESKey));

  const clientAESCtrDecrypt = new AESjs.ModeOfOperation.ctr(clientAESKey, new AESjs.Counter(5));
  var dataBytes = new Buffer(clientAESEncryptedData, 'base64');
  const clientDataBuffer = clientAESCtrDecrypt.decrypt(dataBytes);
  const clientDecryptedData = clientDataBuffer.toString('utf8');
  console.log('clientDecryptedData', clientDecryptedData);

  const clientAESCtrEncrypt = new AESjs.ModeOfOperation.ctr(clientAESKey, new AESjs.Counter(5));
  const message = clientDecryptedData.toUpperCase();
  const aesEncryptedMessage = clientAESCtrEncrypt.encrypt(message).toString('base64');
  console.log('message', message);
  console.log('aesEncryptedMessage', aesEncryptedMessage);

  return res.json({
    data: aesEncryptedMessage
  });
});

// production error handler
// no stacktraces leaked to user
app.use(function (err, req, res, next) {
  res.status(err.status || 500);
  res.json({
    message: err.message,
    error: {}
  });
});

// Start listening
app.listen(3000, function () {
  console.log('Listening on port 3000');
});
