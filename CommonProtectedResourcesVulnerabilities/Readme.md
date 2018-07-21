[index](https://github.com/KiraDiShira/OAuth2/blob/master/README.md#oauth2)

# Common protected resources vulnerabilities

In this chapter, we’re going to learn how to design resource endpoints to minimize the risk of token spoofing and token replay.

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
