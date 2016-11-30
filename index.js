var express = require('express');
var bodyParser = require('body-parser');
var logger = require('morgan');
var NodeRSA = require('node-rsa');

// Configure Web Server
var app = express();
app.use(logger('dev'));
app.use(bodyParser.json());

// Set KEY
var key = new NodeRSA({b: 1024});

console.log('KEY INFO')
console.log('Size: ' + key.getKeySize() + ' bits');
console.log('MaxDataSize: ' + key.getMaxMessageSize() + ' bytes\n');

app.set('pkey', key.exportKey('public'));

// Routes
app.get('/pkey', function (req, res) {
	return res.json({'pkey': app.get('pkey')});
});

app.post('/data', function (req, res) {
	console.log('body: ' + JSON.stringify(req.body));
	return res.json({'message': 'empty'});
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
