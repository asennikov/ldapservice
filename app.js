var config = require('yaml-config');
var settings = config.readConfig('./config/app.yaml');

var express = require('express');
var bodyParser = require('body-parser');
var jwt = require('jwt-simple');
var moment = require('moment');
var LdapAuth = require('ldapauth-fork');
var cors = require('cors');
var redis = require('redis');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cors());

var auth = new LdapAuth({
  url: settings.url,
  searchBase: settings.searchBase,
  searchFilter: settings.searchFilter,
  adminDn: settings.admin.username,
  adminPassword: settings.admin.password,
  timeout: settings.timeout,
  connectTimeout: settings.connectTimeout
});

var redisClient = redis.createClient({
  host: settings.redis.host,
  port: settings.redis.port,
  password: settings.redis.password
});

app.set('jwtTokenSecret', settings.secret);

app.post('/authenticate', function(req, res) {
  if (req.body.username && req.body.password) {
    auth.authenticate(req.body.username, req.body.password, function(err, user) {
      if (err) {
        res.status(401).send({ error: 'Wrong user or password'});
      } else if (user) {
        var expirationInterval = moment.duration(7, 'days');
        var expires = moment().add(expirationInterval).valueOf();
        var token = jwt.encode({
          exp: expires,
          username: user.sAMAccountName,
          groups: user.memberOf,
          mail: user.mail
        }, app.get('jwtTokenSecret'));

        redisClient.setex(token, expirationInterval.asSeconds(), expires, redis.print);

        res.json({
          token : token,
          expires: expires,
          user: {
            'username': user.sAMAccountName,
            'groups': user.memberOf
          }
        });
      }
    });
  } else {
    res.status(401).send({error: "No username or password supplied"});
  }
});

app.listen(settings.listeningPort, function() {
    console.log("Listening on port: " + settings.listeningPort);
});
