var express = require('express');
var bodyParser = require('body-parser');
var logger = require('morgan');
var AESjs = require('aes-js');
var NodeRSA = require('node-rsa');
var crypto = require('./crypto');

// Configure Web Server
var app = express();
app.use(logger('dev'));
app.use(bodyParser.json());

// Set KEY

var cryptoServer = new crypto.Server(2048);
app.set('pkey', cryptoServer.publicKey());

// Routes
app.get('/pkey', function (req, res) {
  return res.json({'pkey': app.get('pkey')});
});

app.post('/data', function (req, res) {
  const body = req.body;
  const cryptoClient = cryptoServer.exchange(body.key);

  const message = cryptoClient.decrypt(body.data);
  console.log('Client message: ', message);

  const response = message.toUpperCase();
  const aesEncryptedResponse = cryptoClient.encrypt(response);
  console.log('Response: ', response);
  console.log('Encrypted response', aesEncryptedResponse);

  return res.json({
    data: aesEncryptedResponse
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
