[index](https://github.com/KiraDiShira/OAuth2/blob/master/README.md#oauth2)

# Common protected resources vulnerabilities

In this chapter, we’re going to learn how to design resource endpoints to minimize the risk of token spoofing and token replay.

- [How are protected resources vulnerable?](#how-are-protected-resources-vulnerable)
- [Design of a protected resource endpoint](#design-of-a-protected-resource-endpoint)
	- [How to protect a resource endpoint](#how-to-protect-a-resource-endpoint)
	- [Adding implicit grant support](#adding-implicit-grant-support)
- [Token replays](#token-replays)

## How are protected resources vulnerable?

The endpoints can be vulnerable to cross-site scripting (XSS) attacks. Indeed, if the resource server chooses to support `access_token` as a URI parameter, the attacker can forge a URI containing the XSS attack and then use social engineering to trick a victim into following that link. When someone clicks on that link,  the malicious JavaScript is then executed. 

**What is XSS?**

Cross-site scripting (XSS) is the Open Web Application Security Project’s (OWASP) Top Ten number three and is by far the most prevalent web application security  flaw. Malicious scripts are injected into otherwise benign and trusted websites to bypass access controls such as the same-origin policy. As a result, an attacker might inject a script and modify the web application to suit their own purposes, such as extracting data that will allow the attacker to impersonate an authenticated user or perhaps to input malicious code for the browser to execute.

## Design of a protected resource endpoint

As a concrete example, we’re going to introduce a new endpoint (`/helloWorld`) together with a new scope (greeting). This new API will look like:

```
GET /helloWorld?language={language}
```

### How to protect a resource endpoint

```js
app.get("/helloWorld", getAccessToken, function(req, res){
	if (req.access_token) {
		if (req.query.language == "en") {
			res.send('Hello World');
		} else if (req.query.language == "de") {
			res.send('Hallo Welt');
		} else if (req.query.language == "it") {
			res.send('Ciao Mondo');
		} else if (req.query.language == "fr") {
			res.send('Bonjour monde');
		} else if (req.query.language == "es") {
			res.send('Hola mundo');
		} else {
			res.send("Error, invalid language: "+ req.query.language);
		}
	}
});
```

Now let’s try hitting the /helloWorld endpoint by passing an invalid language:

```
> curl -v "http://localhost:9002/helloWorld?access_token=TOKEN&language=fi"
```

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 27
Date: Tue, 26 Jan 2016 16:25:00 GMT
Connection: keep-alive

Error, invalid language: fi
```

But as any bug hunter will notice, it seems that the error response of the `/helloWorld` endpoint is designed in a way that the erroneous input bounces back into the response. Let’s try to push this further and pass a nasty payload.

```
> curl -v "http://localhost:9002/helloWorld?access_token=TOKEN&language=<script>alert('XSS')</script>"
```

which will yield:

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 59
Date: Tue, 26 Jan 2016 17:02:16 GMT
Connection: keep-alive

Error, invalid language: <script>alert('XSS')</script>
```

As you can see, the provided payload is returned verbatim and unsanitized. At this point, the suspicion that this endpoint is susceptible to XSS is more than likely true, and the next step is pretty simple. In order to exploit this, an attacker would forge a malicious URI pointing to the protected resource:

```
http://localhost:9002/helloWorld?access_token=TOKEN&language=<script>alert('XSS')</script>
```

When the victim clicks on it, the attack is completed, forcing the JavaScript to execute:

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/CommonProtectedResourcesVulnerabilities/Images/cprv1.PNG" />

At this point, the recommended approach is to properly escape all untrusted data. We’re using URL encoding here.

```js
app.get("/helloWorld", getAccessToken, function(req, res){
	if (req.access_token) {
		if (req.query.language == "en") {
			res.send('Hello World');
		} else if (req.query.language == "de") {
			res.send('Hallo Welt');
		} else if (req.query.language == "it") {
			res.send('Ciao Mondo');
		} else if (req.query.language == "fr") {
			res.send('Bonjour monde');
		} else if (req.query.language == "es") {
			res.send('Hola mundo');
		} else {
			res.send("Error, invalid language: " + querystring.escape(req.query.language));
		}
	}
});
```

With this fix in place now, the error response of the forged request would be something like the following:

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 80
Date: Tue, 26 Jan 2016 17:36:29 GMT
Connection: keep-alive

Error, invalid language:
%3Cscript%3Ealert(%E2%80%98XSS%E2%80%99)%3C%2Fscript%3E
```

Consequently, the browser will render the response without executing the rouge script.

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/CommonProtectedResourcesVulnerabilities/Images/cprv2.PNG" />

The problem with output sanitization is that developers often forget about it, and even if they forget to validate one single input field, we’re back to square one in terms of XSS protection. Browser vendors try hard to stop XSS and ship a series of features as mitigation, one of the most important being returning the right Content-Type for the protected resource endpoint.

Returning the proper Content-Type might save a lot of headaches. Returning to our original unsanitized /helloWorld endpoint, let’s see how we can improve the situation. The original response looked like this:

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 27
Date: Tue, 26 Jan 2016 16:25:00 GMT
Connection: keep-alive

Error, invalid language: fi
```

Here, the Content-Type is `text/html`.

Let’s try using a different Content-Type like `application/json`:

```js
app.get("/helloWorld", getAccessToken, function(req, res){
	if (req.access_token) {
		var resource = {
			"greeting" : ""
		};
		if (req.query.language == "en") {
			res.send('Hello World');
		} else if (req.query.language == "de") {
			res.send('Hallo Welt');
		} else if (req.query.language == "it") {
			res.send('Ciao Mondo');
		} else if (req.query.language == "fr") {
			res.send('Bonjour monde');
		} else if (req.query.language == "es") {
			res.send('Hola mundo');
		} else {
			resource.greeting = "Error, invalid language: "+ req.query.language;
		}
		res.json(resource);
	}
});
```

In this case,

```
> curl -v "http://localhost:9002/helloWorld?access_token=TOKEN&language=en"
```

will return

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 33
Date: Tue, 26 Jan 2016 20:19:05 GMT
Connection: keep-alive

{"greeting": "Hello World"}
```

and

```
> curl -v "http://localhost:9002/helloWorld?access_token=TOKEN&language=<script>alert('XSS')</script>"
```

will yield the following output:

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 76
Date: Tue, 26 Jan 2016 20:21:15 GMT
Connection: keep-alive

{"greeting": "Error, invalid language: <script>alert('XSS')</script>" }
```

If we try this straight in the browser, we can appreciate that having the proper Content-Type immediately stops the attack on its own

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/CommonProtectedResourcesVulnerabilities/Images/cprv3.PNG" />

It’s still entirely possible for a poorly written client application to inject the JSON output into an HTML page without escaping the string, which would lead to the execution of the malicious code. As we said, this is just a mitigation, and it’s still a good practice to always sanitize the output. We combine these into the following:

```js
	else {
		resource.greeting = "Error, invalid language: "+ querystring.
		escape(req.query.language);
	}
}
res.json(resource);
```

This is definitely an improvement, but there is still something more we can do to dial the security up to eleven. One other useful response header supported by all the browsers, with the exception of Mozilla Firefox, is **X-Content-Type-Options: nosniff**.This security header was introduced by Internet Explorer6 to prevent browsers from MIME-sniffing a response away from the declared Content-Type (just in case). 

Another security header is **X-XSS-Protection**, which automatically enables the XSS filter built into most recent web browsers (again with the exception of Mozilla Firefox).

```js
app.get("/helloWorld", getAccessToken, function(req, res){
	if (req.access_token) {
		res.setHeader('X-Content-Type-Options', 'nosniff');
		res.setHeader('X-XSS-Protection', '1; mode=block');
```

Our response will look like this:

```
HTTP/1.1 200 OK
X-Powered-By: Express
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Type: application/json; charset=utf-8
Content-Length: 102
Date: Wed, 27 Jan 2016 17:07:50 GMT
Connection: keep-alive

{
	"greeting": "Error, invalid language:
	%3Cscript%3Ealert(%E2%80%98XSS%E2%80%99)%3C%2Fscript%3E"
}
```

Some room for improvement exists here and it’s called the **Content Security Policy** (CSP). This is yet another response header (Content-Security-Policy) that, quoting the specification, “helps you reduce XSS risks on modern browsers by declaring what dynamic resources are allowed to load via a HTTP Header.”
This topic deserves a chapter of its own and isn’t the main focus of this book; including the proper CSP header field is left as an exercise for the reader.

A resource server can do one final thing to eliminate any chance that a particular endpoint is susceptible to XSS: choose not to support the access_token being passed as a request parameter.8 Doing so would make an XSS on the endpoint theoretically possible but not exploitable because there is no way an attacker can forge a URI that also contains the access token (now expected to be sent in the Authorization: Bearer header). This might sound too restrictive, and there might be valid cases in which using this request parameter is the only possible solution in a particular situation. However, all such cases should be treated as exceptions and approached with proper caution.

### Adding implicit grant support

All the security concerns discussed in the previous section stand, but we need to take care of some extra factors.

When you try to get the resource, you’ll encounter an issue:

```
Cross-Origin Request Blocked: The Same Origin Policy disallows reading the remote resource at http://localhost:9002/helloWorld. (Reason: CORS header ‘Access-Control-Allow-Origin’ missing).
```

What, then, is that all about? The browser is trying to tell us that we’re attempting to do something illegal: we’re trying to use JavaScript to call a URL with a different origin, hence violating the same origin policy that browsers enforce.

**Definition of an origin**

Two pages have the same origin if the protocol, port (if one is specified), and host are the same for both pages. You'll see this referred to as the "scheme/host/port tuple" at times (where a "tuple" is a set of three components that together comprise a whole).

The following table gives examples of origin comparisons to the URL:

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/CommonProtectedResourcesVulnerabilities/Images/cprv4.PNG" />

In particular, from the implicit client running on `http://127.0.0.1:9000`, we’re trying to implement an AJAX request to `http://127.0.0.1:9002`. In essence, the same origin policy states that “browser windows can work in contexts of each other only if they are from served from the same base URL, consisting of `protocol://domain:port`.”

The same origin policy is set up to keep JavaScript inside one page from loading malicious content from another domain. But in this case, it’s fine to allowing a JavaScript call to our API, especially since we’re protecting that API with OAuth to begin with. To solve this, we get a solution straight from the W3C specification: **cross-origin resource sharing (CORS)**.

```
> curl -v -H "Authorization: Bearer TOKEN" http://localhost:9002/helloWorld?language=en
```
with CORS enable gives

```
HTTP/1.1 200 OK
X-Powered-By: Express
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Type: application/json; charset=utf-8
Content-Length: 33
Date: Fri, 29 Jan 2016 17:42:01 GMT
Connection: keep-alive
{
	"greeting": "Hello World"
}
```

This new header tells our browser, which is hosting the JavaScript application, that it’s OK to allow any origin to call this endpoint.

## Token replays

In the previous chapter, we saw how it’s possible to steal an access token. Even if the protected resource runs over HTTPS, once the attacker gets their hands on the access token they will be able to access the protected resource. For this reason, it’s important to have an access token that has a relatively short lifetime to minimize the risk of token replay. Indeed, even if an attacker manages to get hold of a victim access token, if it has already expired (or is close to being expired) the severity of the attack decreases.

One of the main differences of OAuth 2.0 and its predecessor is the fact that the core framework is free of cryptography. Instead, it relies completely on the presence of Transport Layer Security (TLS) across the various connections. For this reason, it’s considered best practice to enforce the usage of TLS as much as possible throughout an OAuth ecosystem. Again, another standard comes to the rescue: **HTTP Strict Transport Security (HSTS)** defined in RFC6797.14 HSTS allows web servers to declare that browsers (or other complying user agents) should interact with it only using secure HTTPS connections, never via the insecure HTTP protocol. Integrating HSTS in our endpoint is straightforward and, like CORS, requires adding a couple of extra headers.

```js
res.setHeader('Strict-Transport-Security', 'max-age=31536000');
```

and now when you try to hit the /helloWorld endpoint from an HTTP client:

```
> curl -v -H "Authorization: Bearer TOKEN" http://localhost:9002/helloWorld?language=en
```

you can notice the HSTS response header

```
HTTP/1.1 200 OK
X-Powered-By: Express
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Content-Type: application/json; charset=utf-8
Content-Length: 33
Date: Fri, 29 Jan 2016 20:13:06 GMT
Connection: keep-alive
{
	"greeting": "Hello World"
}
```

At this point, every time you try to hit the endpoint with the browser using HTTP (not over TLS), you would notice an internal 307 redirect made from the browser. This will avoid any unexpected unencrypted communication (like protocol downgrade attacks). Our test environment doesn’t use TLS at all, so this header effectively makes our resource completely inaccessible. Although this is, of course, very secure, it’s not particularly useful as a resource. A production system with a real API will need to balance both security and accessibility.
