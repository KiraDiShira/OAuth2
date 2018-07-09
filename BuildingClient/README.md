[index](https://github.com/KiraDiShira/OAuth2/blob/master/README.md#oauth2)

# Building a simple OAuth client

we’ll build a simple OAuth client, use
the authorization code grant type to get a bearer access token from an authorization
server, and use that token with a protected resource.

## Getting and using a token

```js
var express = require("express");
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

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
	"redirect_uris": ["http://localhost:9000/callback"]
};

var protectedResource = 'http://localhost:9002/resource';

var state = null;

var access_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', { access_token: access_token, scope: scope });
});

app.get('/authorize', function (req, res) {

	access_token = null;

// 	In the current setup, any time someone comes to http://localhost:9000/
// callback, the client will naively take in the input code value and attempt to post it to
// the authorization server. This would mean that an attacker could use our client to fish
// for valid authorization codes at the authorization server, wasting both client and server
// resources and potentially causing our client to fetch a token it never requested.
// We can mitigate this by using an optional OAuth parameter called state, which
// we’ll fill with a random value and save to a variable on our application. Right after we
// throw out our old access token, we’ll create this value:

	state = randomstring.generate();

	var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: 'code',
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		state: state
	});

	console.log("redirect", authorizeUrl);
	res.redirect(authorizeUrl);
});

app.get('/callback', function (req, res) {

	if (req.query.error) {
		// it's an error response, act accordingly
		res.render('error', { error: req.query.error });
		return;
	}

// 	If the state value doesn’t match what we’re expecting, that’s a very good indication
// that something untoward is happening, such as a session fixation attack, fishing for a
// valid authorization code, or other shenanigans.
	if (req.query.state != state) {
		console.log('State DOES NOT MATCH: expected %s got %s', state, req.query.state);
		res.render('error', { error: 'State value did not match' });
		return;
	}

	var code = req.query.code;

	var form_data = qs.stringify({
		grant_type: 'authorization_code',
		code: code,
		redirect_uri: client.redirect_uris[0]
	});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
	};

	var tokRes = request('POST', authServer.tokenEndpoint, {
		body: form_data,
		headers: headers
	});

	console.log('Requesting access token for code %s', code);

	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());

		access_token = body.access_token;
		console.log('Got access token: %s', access_token);

		res.render('index', { access_token: access_token, scope: scope });
	} else {
		res.render('error', { error: 'Unable to fetch access token, server response: ' + tokRes.statusCode })
	}
});

app.get('/fetch_resource', function (req, res) {

	/*
	 * Use the access token to call the resource server
	 */
	if (!access_token) {
		res.render('error', { error: 'Missing access token.' });
		return;
	}

	var headers = {
		'Authorization': 'Bearer ' + access_token
	};
	var resource = request('POST', protectedResource,
		{ headers: headers }
	);

	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		res.render('data', { resource: body });
		return;
	} else {
		res.render('error', {
			error: 'Server returned response code: ' + resource.
				statusCode
		});
		return;
	}
});

var buildUrl = function (base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function (value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}

	return url.format(newUrl);
};

var encodeClientCredentials = function (clientId, clientSecret) {
	return new Buffer(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
	var host = server.address().address;
	var port = server.address().port;
	console.log('OAuth Client is listening at http://%s:%s', host, port);
});
```

## Refresh tokens

This client has already been set up with an access token and refresh token, but its access token is no longer valid, as if it had expired since it was issued. The client doesn’t know that its access token is currently invalid, so it’s going to try and use it anyway. 

This call to the protected resource is going to fail, and we’ll be programming the client to use its refresh token to get a new access token and try the call to the protected resource again with the new access token.

Is my token any good?

How does an OAuth client know whether its access token is any good? The only real way to be sure is to use it and see what happens. If the token is expected to expire, the authorization server can give a hint as to the expected expiration by using the optional expires_in field of the token response. This is a value in seconds from the time of token issuance that the token is expected to no longer work. A wellbehaved client will pay attention to this value and throw out any tokens that are past the expiration time.
However, knowledge of the expiration alone isn’t sufficient for a client to know the status of the token. In many OAuth implementations, the resource owner can revoke the token before its expiration time. A well-designed OAuth client must always expect that its access token could suddenly stop working at any time, and be able to react accordingly.

```js
var express = require("express");
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var __ = require('underscore');
__.string = require('underscore.string');


var app = express();

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
	"redirect_uris": ["http://localhost:9000/callback"],
	"scope": "foo"
};

var protectedResource = 'http://localhost:9002/resource';

var state = null;

var access_token = '987tghjkiu6trfghjuytrghj';
var scope = null;
var refresh_token = 'j2r3oj32r23rmasd98uhjrk2o3i';

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, scope: scope, refresh_token: refresh_token});
});

app.get('/authorize', function(req, res){

	access_token = null;
	scope = null;
	state = randomstring.generate();
	
	var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: 'code',
		scope: client.scope,
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		state: state
	});
	
	console.log("redirect", authorizeUrl);
	res.redirect(authorizeUrl);
});

app.get('/callback', function(req, res){
	
	if (req.query.error) {
		// it's an error response, act accordingly
		res.render('error', {error: req.query.error});
		return;
	}
	
	var resState = req.query.state;
	if (resState != state) {
		console.log('State DOES NOT MATCH: expected %s got %s', state, resState);
		res.render('error', {error: 'State value did not match'});
		return;
	}

	var code = req.query.code;

	var form_data = qs.stringify({
				grant_type: 'authorization_code',
				code: code,
				redirect_uri: client.redirect_uris[0]
			});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + new Buffer(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64')
	};

	var tokRes = request('POST', authServer.tokenEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);

	console.log('Requesting access token for code %s',code);
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());
	
		access_token = body.access_token;
		console.log('Got access token: %s', access_token);
		if (body.refresh_token) {
			refresh_token = body.refresh_token;
			console.log('Got refresh token: %s', refresh_token);
		}
		
		scope = body.scope;
		console.log('Got scope: %s', scope);

		res.render('index', {access_token: access_token, scope: scope, refresh_token: refresh_token});
	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
	}
});

app.get('/fetch_resource', function(req, res) {

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
		if (refresh_token) {
			refreshAccessToken(req, res);
			return;
		} else {
			res.render('error', {error: resource.statusCode});
			return;
		}
	}
	
	
});

var refreshAccessToken = function(req, res) {
	var form_data = qs.stringify({
		grant_type: 'refresh_token',
		refresh_token: refresh_token
	});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
	};
	console.log('Refreshing token %s', refresh_token);
	var tokRes = request('POST', authServer.tokenEndpoint, {	
			body: form_data,
			headers: headers
	});
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());

		access_token = body.access_token;
		console.log('Got access token: %s', access_token);
		if (body.refresh_token) {
			refresh_token = body.refresh_token;
			console.log('Got refresh token: %s', refresh_token);
		}
		scope = body.scope;
		console.log('Got scope: %s', scope);
	
		// try again
		res.redirect('/fetch_resource');
		return;
	} else {
		console.log('No refresh token, asking the user to get a new access token');
		// tell the user to get a new access token
		refresh_token = null;
		res.render('error', {error: 'Unable to refresh token.'});
		return;
	}
};

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
