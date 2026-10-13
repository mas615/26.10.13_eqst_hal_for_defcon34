var http = require('http');
var fs = require('fs');
var url = require('url');

var server = http.createServer(function(req, res) {
    try {
        var path = url.parse(req.url, true).query;
        path = path['path'];
        if (path.indexOf("..") == -1 && path.indexOf("ＮＮ") == -1) {
            var base = "http://localhost:8080/poems/";
            var fail = function() {
                if (!res.finished) {
                    if (!res.headersSent) {
                        res.writeHead(404);
                    }
                    res.end('Oops');
                }
            };
            var callback = function(response) {
                var str = '';
                response.on('data', function(chunk) {
                    str += chunk;
                });
                response.on('error', fail);
                response.on('end', function() {
                    if (!res.finished) {
                        res.end(str);
                    }
                });
            };
            var upstream = http.get(base + path, callback);
            upstream.on('error', fail);
        } else {
            res.writeHead(403);
            res.end("WHOA THATS BANNED!!!!");
        }
    }
    catch (e) {
        res.writeHead(404);
        res.end('Oops');
    }
});

server.on('clientError', function(error, socket) {
    if (socket.writable) {
        socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    }
});

server.listen(9999);

