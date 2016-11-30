var http = require('http');

http.get({
    host: 'localhost',
    port: 3000,
    path: '/pkey',
}, function(response) {
    // Continuously update stream with data
    var body = '';

    response.on('data', function(d) {
        body += d;
        return
    });

    response.on('end', function() {
        // Data reception is done, do whatever with it!
        var parsed = JSON.parse(body);
        return console.log("Parsed:" + JSON.stringify(parsed));
    });

    return
});