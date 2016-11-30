var express = require('express');
var bodyParser = require('body-parser');
var logger = require('morgan');

var app = express();
app.use(logger('dev'));
app.use(bodyParser.json());

app.get('/publickey', function (req, res) {
	return res.json({'key': 'teste'});
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
