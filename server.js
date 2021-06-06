var express = require('express')
var serveStatic = require('serve-static')

var staticBasePath = './public';
 
var app = express()
 
app.use(serveStatic(staticBasePath))
app.listen(3000)
console.log('Listening on port 3000');