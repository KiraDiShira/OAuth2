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

