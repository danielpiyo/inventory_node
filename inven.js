// import dependencies
const express = require('express');
const http = require('http');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss-clean');

// declare the app
const app = express();// Helmet
app.use(helmet());

// Rate Limiting // security implimentation
const limit = rateLimit({
    max: 100,// max requests
    windowMs: 60 * 60 * 1000, // 1 Hour of 'ban' / lockout 
    message: 'Too many requests' // message to send
});

app.use(xss());

// declare the api route
const api = require('./routes/apiv1')

// enable cors
app.use(cors());

// enable parser for post data
app.use(bodyParser.json({limit: '20kb'}));
app.use(bodyParser.urlencoded({extended:false}));

// catch all routes and return to home
app.get('*', (req,res)=>{
    res.sendFile(path.join(__dirname, './index.html'));
})
// set port for environment and add it to express
const port = process.env.PORT || '3000';
app.set('port', port);
// create http serve
const server = http.createServer(app);
// make the server listen to the already set port
server.listen(port, ()=>{
    console.log(`+++++++++++++++++++++ Email Server Listening on port ${port} ++++++++++++++++++++++++++`)
})
