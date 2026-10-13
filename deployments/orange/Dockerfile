FROM llmctf/2017q-web-orange:latest

COPY server.js /data/server.js

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD nodejs -e "require('http').get('http://127.0.0.1:9999/?path=orange.txt', function(response) { process.exit(response.statusCode === 200 ? 0 : 1); }).on('error', function() { process.exit(1); });"
