[index](https://github.com/KiraDiShira/OAuth2/blob/master/README.md#oauth2)

# OAuth 2.0 in the real world

One of the key areas that OAuth 2.0 can vary is that of the **authorization grant**, colloquially known as the **OAuth flow**.

- Authorization grant types
	- [Implicit grant type](#implicit-grant-type)
	- [Client credentials grant type](#client-credentials-grant-type)
	- [Resource owner credentials grant type](#resource-owner-credentials-grant-type)
	- [Assertion grant types](#assertion-grant-types)
	- [Choosing the appropriate grant type](#choosing-the-appropriate-grant-type)
- Client deployments
	- [Web applications](#web-applications)
	- [Browser applications](#browser-applications)
	- [Native applications](#native-applications)
	- [Handling secrets](#handling-secrets)
	
## Implicit grant type

One key aspect of the different steps in the authorization code flow is that it keeps information separate between different components. This way, the browser doesn’t learn things that only the client should know about, and the client doesn’t get to see the state of the browser, and so on. But what if we were to put the client inside the browser?

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/OAuth2RealWorld/Images/rw1.PNG" />

The client then can’t keep any secrets from the browser, which has full insight into the client’s execution. In this case, there is no real benefit in passing the authorization code through the browser to the client, only to have the client exchange that for a token because the extra layer of secrets isn’t protected against anyone involved.

The implicit grant type does away with this extra secret and its attendant round trip by returning the token directly from the authorization endpoint. The implicit grant type therefore uses only the front channel2 to communicate with the authorization server.

This flow is very useful for JavaScript applications embedded within websites that need to be able to perform an authorized, and potentially limited, session sharing across security domains.

The implicit grant has severe limitations that need to be considered when approaching it. First, there is no realistic way for a client using this flow to keep a client secret, since the secret will be made available to the browser itself. Since this flow uses only the authorization endpoint and not the token endpoint, this limitation does not affect its ability to function, as the client is never expected to authenticate at the authorization endpoint.

However, the lack of any means of authenticating the client does impact the security profile of the grant type and it should be approached with caution. Additionally, the implicit flow can’t be used to get a refresh token. Since in-browser applications are by nature short lived, lasting only the session length of the browser context that has loaded them, the usefulness of a refresh token would be very limited. Furthermore, unlike other grant types, the resource owner can be assumed to be still present in the browser and available to reauthorize the client if necessary.

The client sends its request to the authorization server’s authorization endpoint in the same manner as the authorization code flow, except that this time the response_ type parameter is set to `token` instead of `code`.

The browser makes a request to the authorization server’s authorization endpoint. The resource owner authenticates themselves and authorizes the client in the same manner as the authorization code flow. However, this time the authorization server generates the token immediately and returns it by attaching it to the URI fragment of the response from the authorization endpoint. Remember, since this is the front channel, the response to the client comes in the form of an HTTP redirect back to the client’s redirect URI.

```
GET /callback#access_token=987tghjkiu6trfghjuytrghj&token_type=Bearer
HTTP/1.1
Host: localhost:9000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:39.0)
Gecko/20100101 Firefox/39.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer: http://localhost:9001/authorize?response_type=code&scope=foo&client_
id=oauth-client-1&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcallback&state
=Lwt50DDQKUB8U7jtfLQCVGDL9cnmwHH1
```

The fragment portion of the URI isn’t usually sent back to the server, which means that the token value itself is available only inside the browser. Note, however, that this behavior does vary depending on the browser implementation and version.

When you return from the authorization server, notice that your client comes back with the token value itself in the hash of the redirect URI. The protected resource doesn’t need to do anything different to process and validate this token, but it does need to be configured with cross-origin resource sharing (CORS), which we’ll cover in chapter 8.

```js
var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var qs = require('qs');
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
var clients = [

	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"],
		"scope": "foo bar"
	}
];

var codes = {};

var requests = {};

var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.get("/authorize", function(req, res){
	
	var client = getClient(req.query.client_id);
	
	if (!client) {
		console.log('Unknown client %s', req.query.client_id);
		res.render('error', {error: 'Unknown client'});
		return;
	} else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		console.log('Mismatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
		res.render('error', {error: 'Invalid redirect URI'});
		return;
	} else {
		
		var rscope = req.query.scope ? req.query.scope.split(' ') : undefined;
		var cscope = client.scope ? client.scope.split(' ') : undefined;
		if (__.difference(rscope, cscope).length > 0) {
			var urlParsed = buildUrl(req.query.redirect_uri, {
				error: 'invalid_scope'
			});
			res.redirect(urlParsed);
			return;
		}
		
		var reqid = randomstring.generate(8);
		
		requests[reqid] = req.query;
		
		res.render('approve', {client: client, reqid: reqid, scope: rscope});
		return;
	}

});

app.post('/approve', function(req, res) {

	var reqid = req.body.reqid;
	var query = requests[reqid];
	delete requests[reqid];

	if (!query) {
		// there was no matching saved request, this is an error
		res.render('error', {error: 'No matching authorization request'});
		return;
	}
	
	if (req.body.approve) {
		if (query.response_type == 'code') {
			// user approved access

			var rscope = getScopesFromForm(req.body);
			var client = getClient(query.client_id);
			var cscope = client.scope ? client.scope.split(' ') : undefined;
			if (__.difference(rscope, cscope).length > 0) {
				var urlParsed = buildUrl(query.redirect_uri, {
					error: 'invalid_scope'
				});
				res.redirect(urlParsed);
				return;
			}

			var code = randomstring.generate(8);
			
			// save the code and request for later
			
			codes[code] = { request: query, scope: rscope };
		
			var urlParsed = buildUrl(query.redirect_uri, {
				code: code,
				state: query.state
			});
			res.redirect(urlParsed);
			return;
		} else if (query.response_type == 'token') {
		
			var rscope = getScopesFromForm(req.body);
			var client = getClient(query.client_id);
			var cscope = client.scope ? client.scope.split(' ') : undefined;
			if (__.difference(rscope, cscope).length > 0) {
				var urlParsed = buildUrl(query.redirect_uri,
					{},
					qs.stringify({error: 'invalid_scope'})
				);
				res.redirect(urlParsed);
				return;
			}
			var access_token = randomstring.generate();
			nosql.insert({ access_token: access_token, client_id: client.client_id, scope: rscope });

			var token_response = { access_token: access_token, token_type: 'Bearer', scope: rscope.join(' ') };
			if (query.state) {
				token_response.state = query.state;
			}
		
			var urlParsed = buildUrl(query.redirect_uri,
				{},
				qs.stringify(token_response)
			);
			res.redirect(urlParsed);
			return;
		} else {
			// we got a response type we don't understand
			var urlParsed = buildUrl(query.redirect_uri, {
				error: 'unsupported_response_type'
			});
			res.redirect(urlParsed);
			return;
		}
		
	} else {
		// user denied access
		var urlParsed = buildUrl(query.redirect_uri, {
			error: 'access_denied'
		});
		res.redirect(urlParsed);
		return;
	}
	
});

app.post("/token", function(req, res){
	
	var auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		var clientCredentials = decodeClientCredentials(auth);
		var clientId = clientCredentials.id;
		var clientSecret = clientCredentials.secret;
	}
	
	// otherwise, check the post body
	if (req.body.client_id) {
		if (clientId) {
			// if we've already seen the client's credentials in the authorization header, this is an error
			console.log('Client attempted to authenticate with multiple methods');
			res.status(401).json({error: 'invalid_client'});
			return;
		}
		
		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}
	
	var client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (req.body.grant_type == 'authorization_code') {
		
		var code = codes[req.body.code];
		
		if (code) {
			delete codes[req.body.code]; // burn our code, it's been used
			if (code.request.client_id == clientId) {

				var access_token = randomstring.generate();
				var refresh_token = randomstring.generate();

				nosql.insert({ access_token: access_token, client_id: clientId, scope: code.scope });
				nosql.insert({ refresh_token: refresh_token, client_id: clientId, scope: code.scope });

				console.log('Issuing access token %s', access_token);

				var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: refresh_token, scope: code.scope.join(' ') };

				res.status(200).json(token_response);
				console.log('Issued tokens for code %s', req.body.code);
				
				return;
			} else {
				console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
				res.status(400).json({error: 'invalid_grant'});
				return;
			}
		

		} else {
			console.log('Unknown code, %s', req.body.code);
			res.status(400).json({error: 'invalid_grant'});
			return;
		}
	} else if (req.body.grant_type == 'refresh_token') {
		nosql.one(function(token) {
			if (token.refresh_token == req.body.refresh_token) {
				return token;	
			}
		}, function(err, token) {
			if (token) {
				console.log("We found a matching refresh token: %s", req.body.refresh_token);
				if (token.client_id != clientId) {
					nosql.remove(function(found) { return (found == token); }, function () {} );
					res.status(400).json({error: 'invalid_grant'});
					return;
				}
				var access_token = randomstring.generate();
				nosql.insert({ access_token: access_token, client_id: clientId });
				var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: token.refresh_token };
				res.status(200).json(token_response);
				return;
			} else {
				console.log('No matching token was found.');
				res.status(400).json({error: 'invalid_grant'});
				return;
			}
		});
	} else {
		console.log('Unknown grant type %s', req.body.grant_type);
		res.status(400).json({error: 'unsupported_grant_type'});
	}
});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

var decodeClientCredentials = function(auth) {
	var clientCredentials = new Buffer(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);	
	return { id: clientId, secret: clientSecret };
};

var getScopesFromForm = function(body) {
	return __.filter(__.keys(body), function(s) { return __.string.startsWith(s, 'scope_'); })
				.map(function(s) { return s.slice('scope_'.length); });
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
```

## Client credentials grant type

What if there is no explicit resource owner, or the resource owner is indistinguishable from the client software itself? This is a fairly common situation, in which there are back-end systems that need to communicate directly with each other and not necessarily on behalf of any one particular user. With no user to delegate the authorization to the client, can we even do OAuth?

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/OAuth2RealWorld/Images/rw2.PNG" />

We can, by making use of the client credentials grant type. This flow makes exclusive use of the back channel.

The client requests a token from the token endpoint as it would with the authorization code grant, except that this time it uses the `client_credentials` value for the `grant_type` parameter and doesn’t have an authorization code or other temporary credential to trade for the token. 

Instead, the client authenticates itself directly, and the authorization server issues an appropriate access token. The client can also request specific scopes inside this call using the scope parameter, analogous to the scope parameter used at the authorization endpoint by the authorization code and implicit flows.

```
POST /token
Host: localhost:9001
Accept: application/json
Content-type: application/x-www-form-encoded
Authorization: Basic b2F1dGgtY2xpZW50LTE6b2F1dGgtY2xpZW50LXNlY3JldC0x
grant_type=client_credentials&scope=foo%20bar
```

The response from the authorization server is a normal OAuth token endpoint response: a JSON object containing the token information. The client credentials flow does not issue a refresh token because the client is assumed to be in the position of being able to request a new token for itself at any time without involving a separate resource owner, which renders the refresh token unnecessary in this context.

```
HTTP 200 OK
Date: Fri, 31 Jul 2015 21:19:03 GMT
Content-type: application/json
{
	"access_token": "987tghjkiu6trfghjuytrghj",
	"scope": "foo bar",
	"token_type": "Bearer"
}
```

**Scopes and grant types**

Since the client credentials grant type doesn’t have any direct user interaction, it’s really meant for trusted back-end systems accessing services directly. With that kind of power, it’s often a good idea for protected resources to be able to differentiate between interactive and noninteractive clients when fulfilling requests. A common method of doing this is to use different scopes for both classes of clients, managing them as part of the client’s registration with the authorization server.

**authorizationServer.js**
```js
var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
var clients = [

	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"scope": "foo bar"
	}
];

var codes = {};

var requests = {};

var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.get("/authorize", function(req, res){
	
	var client = getClient(req.query.client_id);
	
	if (!client) {
		console.log('Unknown client %s', req.query.client_id);
		res.render('error', {error: 'Unknown client'});
		return;
	} else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		console.log('Mismatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
		res.render('error', {error: 'Invalid redirect URI'});
		return;
	} else {
		
		var rscope = req.query.scope ? req.query.scope.split(' ') : undefined;
		var cscope = client.scope ? client.scope.split(' ') : undefined;
		if (__.difference(rscope, cscope).length > 0) {
			var urlParsed = buildUrl(req.query.redirect_uri, {
				error: 'invalid_scope'
			});
			res.redirect(urlParsed);
			return;
		}
		
		var reqid = randomstring.generate(8);
		
		requests[reqid] = req.query;
		
		res.render('approve', {client: client, reqid: reqid, scope: rscope});
		return;
	}

});

app.post('/approve', function(req, res) {

	var reqid = req.body.reqid;
	var query = requests[reqid];
	delete requests[reqid];

	if (!query) {
		// there was no matching saved request, this is an error
		res.render('error', {error: 'No matching authorization request'});
		return;
	}
	
	if (req.body.approve) {
		if (query.response_type == 'code') {
			// user approved access

			var rscope = getScopesFromForm(req.body);
			var client = getClient(query.client_id);
			var cscope = client.scope ? client.scope.split(' ') : undefined;
			if (__.difference(rscope, cscope).length > 0) {
				var urlParsed = buildUrl(query.redirect_uri, {
					error: 'invalid_scope'
				});
				res.redirect(urlParsed);
				return;
			}

			var code = randomstring.generate(8);
			
			// save the code and request for later
			
			codes[code] = { request: query, scope: rscope };
		
			var urlParsed = buildUrl(query.redirect_uri, {
				code: code,
				state: query.state
			});
			res.redirect(urlParsed);
			return;
		} else {
			// we got a response type we don't understand
			var urlParsed = buildUrl(query.redirect_uri, {
				error: 'unsupported_response_type'
			});
			res.redirect(urlParsed);
			return;
		}
	} else {
		// user denied access
		var urlParsed = buildUrl(query.redirect_uri, {
			error: 'access_denied'
		});
		res.redirect(urlParsed);
		return;
	}
	
});

app.post("/token", function(req, res){
	
	var auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		var clientCredentials = decodeClientCredentials(auth);
		var clientId = clientCredentials.id;
		var clientSecret = clientCredentials.secret;
	}
	
	// otherwise, check the post body
	if (req.body.client_id) {
		if (clientId) {
			// if we've already seen the client's credentials in the authorization header, this is an error
			console.log('Client attempted to authenticate with multiple methods');
			res.status(401).json({error: 'invalid_client'});
			return;
		}
		
		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}
	
	var client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (req.body.grant_type == 'authorization_code') {
		
		var code = codes[req.body.code];
		
		if (code) {
			delete codes[req.body.code]; // burn our code, it's been used
			if (code.request.client_id == clientId) {

				var access_token = randomstring.generate();
				var refresh_token = randomstring.generate();

				nosql.insert({ access_token: access_token, client_id: clientId, scope: code.scope });
				nosql.insert({ refresh_token: refresh_token, client_id: clientId, scope: code.scope });

				console.log('Issuing access token %s', access_token);

				var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: refresh_token, scope: code.scope.join(' ') };

				res.status(200).json(token_response);
				console.log('Issued tokens for code %s', req.body.code);
				
				return;
			} else {
				console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
				res.status(400).json({error: 'invalid_grant'});
				return;
			}
		

		} else {
			console.log('Unknown code, %s', req.body.code);
			res.status(400).json({error: 'invalid_grant'});
			return;
		}
		
	} else if (req.body.grant_type == 'client_credentials') {
		var rscope = req.body.scope ? req.body.scope.split(' ') : undefined;
		var cscope = client.scope ? client.scope.split(' ') : undefined;
		if (__.difference(rscope, cscope).length > 0) {
			res.status(400).json({error: 'invalid_scope'});
			return;
		}
		var access_token = randomstring.generate();
		var token_response = { access_token: access_token, token_type: 'Bearer', scope: rscope.join(' ') };
		nosql.insert({ access_token: access_token, client_id: clientId, scope: rscope });
		res.status(200).json(token_response);
		return;	
			
	} else if (req.body.grant_type == 'refresh_token') {
		nosql.one(function(token) {
			if (token.refresh_token == req.body.refresh_token) {
				return token;	
			}
		}, function(err, token) {
			if (token) {
				console.log("We found a matching refresh token: %s", req.body.refresh_token);
				if (token.client_id != clientId) {
					nosql.remove(function(found) { return (found == token); }, function () {} );
					res.status(400).json({error: 'invalid_grant'});
					return;
				}
				var access_token = randomstring.generate();
				nosql.insert({ access_token: access_token, client_id: clientId });
				var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: token.refresh_token };
				res.status(200).json(token_response);
				return;
			} else {
				console.log('No matching token was found.');
				res.status(400).json({error: 'invalid_grant'});
				return;
			}
		});
	} else {
		console.log('Unknown grant type %s', req.body.grant_type);
		res.status(400).json({error: 'unsupported_grant_type'});
	}
});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

var decodeClientCredentials = function(auth) {
	var clientCredentials = new Buffer(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);	
	return { id: clientId, secret: clientSecret };
};

var getScopesFromForm = function(body) {
	return __.filter(__.keys(body), function(s) { return __.string.startsWith(s, 'scope_'); })
				.map(function(s) { return s.slice('scope_'.length); });
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
```

**client.js**
```js
var express = require("express");
var bodyParser = require('body-parser');
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var base64url = require('base64url');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information

var client = {
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1",
	"scope": "foo bar"
};

//var client = {};

var protectedResource = 'http://localhost:9002/resource';

var state = null;

var access_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, scope: scope});
});

app.get('/authorize', function(req, res){

	access_token = null;
	scope = null;
	
	var form_data = qs.stringify({
		grant_type: 'client_credentials',
		scope: client.scope
	});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
	};

	var tokRes = request('POST', authServer.tokenEndpoint, {	
		body: form_data,
		headers: headers
	});
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());
	
		access_token = body.access_token;

		scope = body.scope;

		res.render('index', {access_token: access_token, scope: scope});
	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
	}
	
});

app.get('/fetch_resource', function(req, res) {

	if (!access_token) {
		res.render('error', {error: 'Missing access token.'});
		return;
	}
	
	console.log('Making request with access token %s', access_token);
	
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('POST', protectedResource,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		res.render('data', {resource: body});
		return;
	} else {
		access_token = null;
		res.render('error', {error: 'Server returned response code: ' + resource.statusCode});
		return;
	}
	
});

var encodeClientCredentials = function(clientId, clientSecret) {
	return new Buffer(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
```

## Resource owner credentials grant type

If the resource owner has a plain username and password at the authorization server, then it could be possible for the client to prompt the user for these credentials and trade them for an access token. The resource owner credentials grant type, also known as the password flow, allows a client to do just that. The resource owner interacts directly with the client and never with the authorization server itself. The grant type uses the token endpoint exclusively, remaining confined to the back channel.

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/OAuth2RealWorld/Images/rw3.PNG" />

This method should sound eerily familiar to you at this point. “Wait a minute,” you may be thinking, “we covered this back in chapter 1 and you said it was a bad idea!” And you’d be correct: this grant type, which is included in the core OAuth specification, is based on the “ask for the keys” antipattern. And, in general, it’s a bad idea.

The way that the grant type works is simple. The client collect’s the resource owner’s username and password, using whatever interface it has at its disposal, and replays that at the authorization server.

```
POST /token
Host: localhost:9001
Accept: application/json
Content-type: application/x-www-form-encoded
Authorization: Basic b2F1dGgtY2xpZW50LTE6b2F1dGgtY2xpZW50LXNlY3JldC0x
grant_type=password&scope=foo%20bar&username=alice&password=secret
```

The authorization server reads the username and password off the incoming request and compares it with its local user store. If they match, the authorization server issues a token for that resource owner. If you think this looks a lot like a man-in-the-middle attack, you’re not far off. You know that you’re not supposed to do this, and why, but we’re going to work through how to build it so that you know what not to build in the future, if you can avoid it.

Now that you know how to use this grant type, if you can at all avoid it, please don’t do it in real life. This grant type should be used only to bridge clients that would otherwise be dealing with a direct username and password into the OAuth world, and such clients should instead use the authorization code flow in almost all cases as soon as possible. As such, don’t use this grant type unless you have no other choice. The internet thanks you.

**authorizationServer.js**
```js
var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
var clients = [

	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"scope": "foo bar"
	}
];

var userInfo = {

	"alice": {
		"sub": "9XE3-JI34-00132A",
		"preferred_username": "alice",
		"name": "Alice",
		"email": "alice.wonderland@example.com",
		"email_verified": true,
		"password": "password"
	},
	
	"bob": {
		"sub": "1ZT5-OE63-57383B",
		"preferred_username": "bob",
		"name": "Bob",
		"email": "bob.loblob@example.net",
		"email_verified": false,
		"password": "this is my secret password"
	},

	"carol": {
		"sub": "F5Q1-L6LGG-959FS",
		"preferred_username": "carol",
		"name": "Carol",
		"email": "carol.lewis@example.net",
		"email_verified": true,
		"username" : "clewis",
		"password" : "user password!"
 	}	
};

var codes = {};

var requests = {};

var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

var getUser = function(username) {
	return userInfo[username];
};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.get("/authorize", function(req, res){
	
	var client = getClient(req.query.client_id);
	
	if (!client) {
		console.log('Unknown client %s', req.query.client_id);
		res.render('error', {error: 'Unknown client'});
		return;
	} else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		console.log('Mismatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
		res.render('error', {error: 'Invalid redirect URI'});
		return;
	} else {
		
		var rscope = req.query.scope ? req.query.scope.split(' ') : undefined;
		var cscope = client.scope ? client.scope.split(' ') : undefined;
		if (__.difference(rscope, cscope).length > 0) {
			var urlParsed = buildUrl(req.query.redirect_uri, {
				error: 'invalid_scope'
			});
			res.redirect(urlParsed);
			return;
		}
		
		var reqid = randomstring.generate(8);
		
		requests[reqid] = req.query;
		
		res.render('approve', {client: client, reqid: reqid, scope: rscope});
		return;
	}

});

app.post('/approve', function(req, res) {

	var reqid = req.body.reqid;
	var query = requests[reqid];
	delete requests[reqid];

	if (!query) {
		// there was no matching saved request, this is an error
		res.render('error', {error: 'No matching authorization request'});
		return;
	}
	
	if (req.body.approve) {
		if (query.response_type == 'code') {
			// user approved access

			var rscope = getScopesFromForm(req.body);
			var client = getClient(query.client_id);
			var cscope = client.scope ? client.scope.split(' ') : undefined;
			if (__.difference(rscope, cscope).length > 0) {
				var urlParsed = buildUrl(query.redirect_uri, {
					error: 'invalid_scope'
				});
				res.redirect(urlParsed);
				return;
			}

			var code = randomstring.generate(8);
			
			// save the code and request for later
			
			codes[code] = { request: query, scope: rscope };
		
			var urlParsed = buildUrl(query.redirect_uri, {
				code: code,
				state: query.state
			});
			res.redirect(urlParsed);
			return;
		} else {
			// we got a response type we don't understand
			var urlParsed = buildUrl(query.redirect_uri, {
				error: 'unsupported_response_type'
			});
			res.redirect(urlParsed);
			return;
		}
	} else {
		// user denied access
		var urlParsed = buildUrl(query.redirect_uri, {
			error: 'access_denied'
		});
		res.redirect(urlParsed);
		return;
	}
	
});

app.post("/token", function(req, res){
	
	var auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		var clientCredentials = decodeClientCredentials(auth);
		var clientId = clientCredentials.id;
		var clientSecret = clientCredentials.secret;
	}
	
	// otherwise, check the post body
	if (req.body.client_id) {
		if (clientId) {
			// if we've already seen the client's credentials in the authorization header, this is an error
			console.log('Client attempted to authenticate with multiple methods');
			res.status(401).json({error: 'invalid_client'});
			return;
		}
		
		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}
	
	var client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (req.body.grant_type == 'authorization_code') {
		
		var code = codes[req.body.code];
		
		if (code) {
			delete codes[req.body.code]; // burn our code, it's been used
			if (code.request.client_id == clientId) {

				var access_token = randomstring.generate();
				var refresh_token = randomstring.generate();

				nosql.insert({ access_token: access_token, client_id: clientId, scope: code.scope });
				nosql.insert({ refresh_token: refresh_token, client_id: clientId, scope: code.scope });

				console.log('Issuing access token %s', access_token);

				var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: refresh_token, scope: code.scope.join(' ') };

				res.status(200).json(token_response);
				console.log('Issued tokens for code %s', req.body.code);
				
				return;
			} else {
				console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
				res.status(400).json({error: 'invalid_grant'});
				return;
			}
		

		} else {
			console.log('Unknown code, %s', req.body.code);
			res.status(400).json({error: 'invalid_grant'});
			return;
		}
	
	} else if (req.body.grant_type == 'password') {
		var username = req.body.username;
		var user = getUser(username);
		if (!user) {
			res.status(401).json({error: 'invalid_grant'});
			return;
		}
		var password = req.body.password;
		if (user.password != password) {
			console.log('Mismatched resource owner password, expected %s got %s', user.password, password);
			res.status(401).json({error: 'invalid_grant'});
			return;
		}
		var rscope = req.body.scope ? req.body.scope.split(' ') : undefined;
		var cscope = client.scope ? client.scope.split(' ') : undefined;
		if (__.difference(rscope, cscope).length > 0) {
			res.status(401).json({error: 'invalid_scope'});
			return;
		}
		var access_token = randomstring.generate();
		var refresh_token = randomstring.generate();

		nosql.insert({ access_token: access_token, client_id: clientId, scope: rscope });
		nosql.insert({ refresh_token: refresh_token, client_id: clientId, scope: rscope });

		var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: refresh_token, scope: rscope.join(' ') };

		res.status(200).json(token_response);

	} else if (req.body.grant_type == 'refresh_token') {
		nosql.one(function(token) {
			if (token.refresh_token == req.body.refresh_token) {
				return token;	
			}
		}, function(err, token) {
			if (token) {
				console.log("We found a matching refresh token: %s", req.body.refresh_token);
				if (token.client_id != clientId) {
					nosql.remove(function(found) { return (found == token); }, function () {} );
					res.status(400).json({error: 'invalid_grant'});
					return;
				}
				var access_token = randomstring.generate();
				nosql.insert({ access_token: access_token, client_id: clientId });
				var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: token.refresh_token };
				res.status(200).json(token_response);
				return;
			} else {
				console.log('No matching token was found.');
				res.status(400).json({error: 'invalid_grant'});
				return;
			}
		});
	} else {
		console.log('Unknown grant type %s', req.body.grant_type);
		res.status(400).json({error: 'unsupported_grant_type'});
	}
});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

var decodeClientCredentials = function(auth) {
	var clientCredentials = new Buffer(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);	
	return { id: clientId, secret: clientSecret };
};

var getScopesFromForm = function(body) {
	return __.filter(__.keys(body), function(s) { return __.string.startsWith(s, 'scope_'); })
				.map(function(s) { return s.slice('scope_'.length); });
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
```

**client.js**
```js
var express = require("express");
var bodyParser = require('body-parser');
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var jose = require('jsrsasign');
var base64url = require('base64url');
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information

var client = {
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1",
	"scope": "foo bar"
};

//var client = {};

var protectedResource = 'http://localhost:9002/resource';

var state = null;

var access_token = null;
var scope = null;
var refresh_token = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
});

app.get('/authorize', function(req, res) {
	// this renders the username/password form
	res.render('username_password');
	return;
});

app.post('/username_password', function(req, res) {
	var username = req.body.username;
	var password = req.body.password;
	
	var form_data = qs.stringify({
		grant_type: 'password',
		username: username,
		password: password,
		scope: client.scope
	});
	
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
	};

	var tokRes = request('POST', authServer.tokenEndpoint, {	
		body: form_data,
		headers: headers
	});
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());
	
		access_token = body.access_token;

		scope = body.scope;

		res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
	}
});

app.get('/fetch_resource', function(req, res) {

	if (!access_token) {
		res.render('error', {error: 'Missing access token.'});
		return;
	}
	
	console.log('Making request with access token %s', access_token);
	
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('POST', protectedResource,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		res.render('data', {resource: body});
		return;
	} else {
		access_token = null;
		res.render('error', {error: 'Server returned response code: ' + resource.statusCode});
		return;
	}
	
});

var encodeClientCredentials = function(clientId, clientSecret) {
	return new Buffer(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
```

# Assertion grant types

the assertion grant types, the client is given a structured and cryptographically protected item called an assertion to give to the authorization server in exchange for a token.

Two formats are standardized so far: one using Security Assertion Markup Language (SAML),4 and another using JSON Web Token (JWT)5 (which we’ll cover in chapter 11). This grant type uses the back channel exclusively, and much like the client credentials flow there may not be an explicit resource owner involved. Unlike the client credentials flow, the rights associated with the resulting token are determined by the assertion being presented and not solely by the client itself. Since the assertion generally comes from a third party external to the client, the client can remain unaware of the nature of the assertion itself.

Like other back-channel flows, the client makes an HTTP POST to the authorization server’s token endpoint. The client authenticates itself as usual and includes the assertion as a parameter. The means by which the client can get this assertion vary wildly, and are considered out of scope by many of the associated protocols. The client could be handed the assertion by a user, or by a configuration system, or through  another non-OAuth protocol. In the end, as with an access token, it doesn’t matter how the client got the assertion as long as it’s able to present the assertion to the authorization server. In this example, the client is presenting a JWT assertion, which is reflected in the value of the grant_type parameter.

```js
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic b2F1dGgtY2xpZW50LTE6b2F1dGgtY2xpZW50LXNlY3JldC0x
grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
&assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0xIn0.eyJpc3MiOi
JodHRwOi8vdHJ1c3QuZXhhbXBsZS5uZXQvIiwic3ViIjoib2F1dGgtY2xpZW50LTEiLCJzY29wZSI
6ImZvbyBiYXIgYmF6IiwiYXVkIjoiaHR0cDovL2F1dGhzZXJ2ZXIuZXhhbXBsZS5uZXQvdG9rZW4i
LCJpYXQiOjE0NjU1ODI5NTYsImV4cCI6MTQ2NTczMzI1NiwianRpIjoiWDQ1cDM1SWZPckRZTmxXO
G9BQ29Xb1djMDQ3V2J3djIifQ.HGCeZh79Va-7meazxJEtm07ZyptdLDu_Ocfw82F1zAT2p6Np6Ia_
vEZTKzGhI3HdqXsUG3uDILBv337VNweWYE7F9ThNgDVD90UYGzZN5VlLf9bzjnB2CDjUWXBhgepSy
aSfKHQhfyjoLnb2uHg2BUb5YDNYk5oqaBT_tyN7k_PSopt1XZyYIAf6-5VTweEcUjdpwrUUXGZ0fl
a8s6RIFNosqt5e6j0CsZ7Eb_zYEhfWXPo0NbRXUIG3KN6DCA-ES6D1TW0Dm2UuJLb-LfzCWsA1W_
sZZz6jxbclnP6c6Pf8upBQIC9EvXqCseoPAykyR48KeW8tcd5ki3_tPtI7vA
```

The body of this example assertion translates to the following:

```js
{
	"iss": "http://trust.example.net/",
	"sub": "oauth-client-1",
	"scope": "foo bar baz",
	"aud": "http://authserver.example.net/token",
	"iat": 1465582956,
	"exp": 1465733256,
	"jti": "X45p35IfOrDYNlW8oACoWoWc047Wbwv2"
}
```

The authorization server parsers the assertion, checks its cryptographic protection, and processes its contents to determine what kind of token to generate. This assertion can represent any number of different things, such as a resource owner’s identity or a set of allowed scopes. The authorization server will generally have a policy that determines the parties that it will accept assertions from and rules for what those assertions mean. In the end, it generates an access token as with any other response from the token endpoint. The client can then take this token and use it at the protected resource in the normal fashion.

In the real world, you’re likely to see assertions used only in limited, usually enterprise, contexts.

## Choosing the appropriate grant type

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/OAuth2RealWorld/Images/rw4.PNG" />

# Client deployments

OAuth clients come in many different forms and styles, but they can be broadly categorized into one of three categories: web applications, in-browser applications, and native applications. Each of these has its own strengths and weaknesses, and we’ll cover them in turn.

## Web applications

These applications are able to make full use of both front- and back-channel communication methods.

Because of this flexibility, web applications can easily use the authorization code, client credentials, or assertions flows most effectively. Since the fragment component of the request URI isn’t usually passed to the server by the browser, the implicit flow doesn’t work for web applications in most circumstances.

## Browser applications

These clients can easily use the front channel, as sending the user to another page through an HTTP redirect is trivial. Responses from the front channel are also simple, as the client’s software does need to be loaded from a web server. However, backchannel communication is more complicated, as browser applications are limited by same-origin policies and other security restrictions designed to prevent cross-domain attacks. Consequently, these types of applications are best suited for the implicit flow, which has been optimized for this case.

Let’s take a hands-on look at a browser application. Open up ch-6-ex-4 and edit files/client/index.html.

```js

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <title>OAuth in Action: OAuth Client</title>

    <!-- Bootstrap -->
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
  <style>
  body {
    padding-top: 60px;
  }
  .navbar-inverse {
    background-color: #223;
  }
  </style>
    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
  </head>
  <body>

    <nav class="navbar navbar-inverse navbar-fixed-top">
      <div class="container">
        <div class="navbar-header">
          <a class="navbar-brand" href="/">OAuth in Action: <span class="label label-primary">OAuth Client</label></a>
        </div>
      </div>
    </nav>

    <div class="container">

      <div class="jumbotron">
      <p>Scope value: <span class="label label-danger oauth-scope-value"></span></p>
      <p>Access token value: <span class="label label-danger oauth-access-token"></span></p>
      <button class="btn btn-default oauth-authorize" type="button">Get OAuth Token</button> 
      <button class="btn btn-default oauth-fetch-resource" type="button">Get Protected Resource</button>
      </div>
      <div class="jumbotron">
      <h2>Data from protected resource:</h2>
      <pre><span class="oauth-protected-resource"</pre>
      </div>
    </div><!-- /.container -->

  
  
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>

    <script>

      (function () {
        var callbackData;

        // client information
        var client = {
          'client_id': 'oauth-client-1',
          'redirect_uris': ['http://localhost:9000/callback'],
          'scope': 'foo bar'
        };

        // authorization server information
        var authServer = {
          authorizationEndpoint: 'http://localhost:9001/authorize'
        };

        var protectedResource = 'http://localhost:9002/resource';

        function generateState(len) {
          var ret = '';
          var possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

          for (var i=0; i < len; i++) {
            // add random character
            ret += possible.charAt(Math.floor(Math.random() * possible.length));  
          }
          
          return ret;
        }  

        function handleAuthorizationRequestClick(ev) {
          var state = generateState(32);

          localStorage.setItem('oauth-state', state);

          location.href = authServer.authorizationEndpoint + '?' + 
            'response_type=token' +
            '&state=' + state +
            '&scope=' + encodeURIComponent(client.scope) + 
            '&client_id=' + encodeURIComponent(client.client_id) +
            '&redirect_uri=' + encodeURIComponent(client.redirect_uris[0]);
        }

        function handleFetchResourceClick(ev) {
          if (callbackData != null ) {

            $.ajax({
              url: protectedResource,
              type: 'POST',
              crossDomain: true,
              dataType: 'json',
              headers: {
                'Authorization': 'Bearer ' + callbackData.access_token
              }
            }).done(function(data) {
              $('.oauth-protected-resource').text(JSON.stringify(data));
            }).fail(function() {
              $('.oauth-protected-resource').text('Error while fetching the protected resource');
            });

          }
        }

        function processCallback() {
          var h = location.hash.substring(1);
          var whitelist = ['access_token', 'state']; // for parameters

          callbackData = {};

          h.split('&').forEach(function (e) {
            var d = e.split('=');

            if (whitelist.indexOf(d[0]) > -1) {
              callbackData[d[0]] = d[1];  
            }
          });

          if (callbackData.state !== localStorage.getItem('oauth-state')) {
            console.log('State DOES NOT MATCH: expected %s got %s', localStorage.getItem('oauth-state'), callbackData.state);
            callbackData = null;
            $('.oauth-protected-resource').text("Error state value did not match");
          } else {
            $('.oauth-access-token').text(callbackData.access_token);
            console.log('access_token: ', callbackData.access_token);
          }
        }

        // fill placeholder on UI
        $('.oauth-scope-value').text(client.scope);

        // UI button click handler
        $('.oauth-authorize').on('click', handleAuthorizationRequestClick);
        $('.oauth-fetch-resource').on('click', handleFetchResourceClick);
        
        // we got a hash as a callback
        if (location.hash) {
          processCallback();
        }

      }());
            
    </script>
  </body>
</html>

```

## Native applications

Native applications are those that run directly on the end user’s device, be it a computer or mobile platform. The software for the application is generally compiled or packaged externally and then installed on the device. These applications can easily make use of the back channel by making a direct HTTP call outbound to the remote server. Since the user isn’t in a web browser, as they are with a web application or a browser client, the front channel is more problematic.

To make a front-channel request, the native application needs to be able to reach out to the system web browser or an embedded browser view to get the user to the authorization server directly. To listen for front-channel responses, the native application needs to be able to serve a URI that the browser can be redirected to by the authorization server. This usually takes one of the following forms:

- An embedded web server running on localhost
- A remote web server with some type of out-of-band push notification capability to the application
- A custom URI scheme such as `com.oauthinaction.mynativeapp:/` that is registered with the operating system such that the application is called when URIs with that scheme are accessed

For mobile applications, the custom URI scheme is the most common. Native applications are capable of using the authorization code, client credentials, or assertion flows easily, but because they can keep information out of the web browser, it is not recommended that native applications use the implicit flow.

The first thing to notice is the client configuration.

```js
var client = {
	"client_id": "native-client-1",
	"client_secret": "oauth-native-secret-1",
	"redirect_uris": ["com.oauthinaction.mynativeapp:/"],
	"scope": "foo bar"
};
```
As you can see, the registration details are same as they are for a normal OAuth client. One thing that might catch your attention is the registered redirect_uris. This is different from a traditional client because it uses a custom URI scheme, `com.oauthinaction.mynativeapp:/` in this case, rather than a more traditional `https://`. Whenever the system browser sees a URL starting with com.oauthinaction .mynativeapp:/, whether it’s from a link clicked by the user or an HTTP redirect from another page or from an explicit launch from another application, our application will get called using a special handler. Inside this handler, we have access to the full URL string that was used in the link or redirect, just as if we were a web server serving the URL through HTTP.

**Keeping secrets in native applications**

In our exercise, we’re using a client secret that’s been configured directly into the client as we did with the web application in chapter 3. In a production native application, our exercise’s approach doesn’t work very well because each copy of the application would have access to the secret, which of course doesn’t make it very secret. A few alternative options are available to use in practice. We’ll cover this issue in greater detail in section 6.2.4

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <title>OAuth in Action: OAuth Native Client</title>
    <link href="css/style.css" rel="stylesheet">
    <script type="text/javascript" src="cordova.js"></script>
    <script type="text/javascript" src="js/jquery.min.js"></script>
  </head>
  <body>

    <header>OAuth in Action</header>

    <div class="page">
      
      <div class="block">
        <p>Scope value: <br><span class="label label-danger oauth-scope-value"></span></p>
        <p>Access token value: <br><span class="label label-danger oauth-access-token"></span></p>
      </div>

      <div class="block">
        <button class="oauth-authorize" type="button">Get OAuth Token</button> 
        <button class="oauth-fetch-resource" type="button">Get Protected Resource</button>
      </div>

      <div class="block">
        <div>Data from protected resource:</div>
        <div>
          <pre class="oauth-protected-resource"></pre>
        </div>
      </div>

    </div>  

    <script>

      function handleOpenURL(url) {
        setTimeout(function() {
          processCallback(url.substr(url.indexOf('?') + 1));
        }, 0);
      }
 
      var callbackData;

      // client information
      var client = {
        'client_id': 'native-client-1',
        'client_secret': 'oauth-native-secret-1',
        'redirect_uris': ['com.oauthinaction.mynativeapp://'],
        'scope': 'foo bar'
      };

      // authorization server information
      var authServer = {
        authorizationEndpoint: 'http://localhost:9001/authorize',
        tokenEndpoint: 'http://localhost:9001/token'
      };

      var protectedResource = 'http://localhost:9002/resource';

      function generateState(len) {
        var ret = '';
        var possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

        for (var i=0; i < len; i++) {
          // add random character
          ret += possible.charAt(Math.floor(Math.random() * possible.length));  
        }
        
        return ret;
      }  

      function handleAuthorizationRequestClick(ev) {
        var state = generateState(32);

        localStorage.setItem('oauth-state', state);
        
        var url = authServer.authorizationEndpoint + '?' +
                'response_type=code' +
                '&state=' + state +
                '&scope=' + encodeURIComponent(client.scope) +
                '&client_id=' + encodeURIComponent(client.client_id) +
                '&redirect_uri=' + encodeURIComponent(client.redirect_uris[0]);

        cordova.InAppBrowser.open(url, '_system');
         
      }

      function handleFetchResourceClick(ev) {
        if (callbackData != null ) {

          $.ajax({
            url: protectedResource,
            type: 'POST',
            crossDomain: true,
            dataType: 'json',
            headers: {
              'Authorization': 'Bearer ' + callbackData.access_token
            }
          }).done(function(data) {
            $('.oauth-protected-resource').text(JSON.stringify(data));
          }).fail(function() {
            $('.oauth-protected-resource').text('Error while fetching the protected resource');
          });

        }
      }

      function processCallback(h) {
        var whitelist = ['code', 'state']; // for parameters

        callbackData = {};

        h.split('&').forEach(function (e) {
          var d = e.split('=');

          if (whitelist.indexOf(d[0]) > -1) {
            callbackData[d[0]] = d[1];  
          }
        });          

        if (callbackData.state !== localStorage.getItem('oauth-state')) {
          console.log('State DOES NOT MATCH: expected %s got %s', localStorage.getItem('oauth-state'), callbackData.state);
          callbackData = null;
          $('.oauth-protected-resource').text("Error state value did not match");
        } else {
          $.ajax({
            url: authServer.tokenEndpoint,
            type: 'POST',
            crossDomain: true,
            dataType: 'json',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'                 
            },
            data: {
              grant_type: 'authorization_code',
              code: callbackData.code,
              client_id: client.client_id,
              client_secret: client.client_secret,
            }
          }).done(function(data) {
            $('.oauth-access-token').text(data.access_token);
            callbackData.access_token = data.access_token;
          }).fail(function() {
            $('.oauth-protected-resource').text('Error while getting the access token');
          });

        }
      }

      // fill placeholder on UI
      $('.oauth-scope-value').text(client.scope);

      // UI button click handler
      $('.oauth-authorize').on('click', handleAuthorizationRequestClick);
      $('.oauth-fetch-resource').on('click', handleFetchResourceClick);
 
            
    </script>
  </body>
</html>
```

## Handling secrets

The purpose of the client secret is to let an instance of client software authenticate itself to the authorization server, apart from any authorizations conferred to it by the resource owner. The client secret isn’t available to the resource owner or the browser, allowing it to uniquely identify the client software application.

The problem comes from needing to differentiate between **configuration time secrets**, which every copy of a client gets, and **runtime secrets**, which are distinct for each instance. Client secrets are configuration time secrets because they represent the client software itself and are configured into the client software.

Access tokens, refresh tokens, and authorization codes are all runtime secrets because they’re stored by the client software after it is deployed and running. Runtime secrets do still need to be stored securely and protected appropriately, but they’re designed to be easily revocable and rotatable. Configuration time secrets, in contrast, are generally things that aren’t expected to change often.

In OAuth 2.0, this dichotomy is addressed by removing the requirement for all clients to have a client secret and instead defining two classes of clients, **public clients** and **confidential clients**, based on their ability to keep a configuration time secret.

Public clients, as the name suggests, are unable to hold configuration time secrets and therefore have no client secret. This is usually because the code for the client is exposed to the end user in some fashion, either by being downloaded and executed in a browser or by executing natively on the user’s device. Consequently, most browser applications and many native applications are public clients. In either case, each copy of the client software is identical and there are potentially many instances of it. The user of any instance could extract the configuration information for that instance, including any configured client ID and client secret. Although all instances share the same client ID, this doesn’t cause a problem because the client ID isn’t intended to be a secret value. Anyone attempting to impersonate this client by copying its client ID will still need to use its redirect URIs and be bound by other measures. Having an additional client secret, in this case, does no good because it could be extracted and copied along with the client ID.

A potential mitigation is available for applications that use the authorization code flow in the form of **Proof Key for Code Exchange** (PKCE), discussed in chapter 10. The PKCE protocol extension allows a client to more tightly bind its initial request to the authorization code that it receives, but without using a client secret or equivalent.

Confidential clients are able to hold configuration time secrets. Each instance of the client software has a distinct configuration, including its client ID and secret, and these values are difficult to extract by end users. A web application is the most common type of confidential client, as it represents a single instance running on a web server that can handle multiple resource owners with a single OAuth client. The client ID can be gathered as it is exposed through the web browser, but the client secret is passed only in the back channel and is never directly exposed.

An alternative approach to this problem is to use **dynamic client registration**, discussed in depth in chapter 12. By using dynamic client registration, an instance of a piece of client software can register itself at runtime. This effectively turns what would otherwise need to be a configuration time secret into a runtime secret, allowing a higher level of security and functionality to clients that would otherwise be unable to use it.
