[index](https://github.com/KiraDiShira/OAuth2/blob/master/README.md#oauth2)

# Common authorization server vulnerabilities

- [Session hijacking](#session-hijacking)
- [Client impersonation](#client-impersonation)

## Session hijacking

To obtain an access token in the authorization code grant flow, the client needs to take an intermediate step involving the authorization server producing an authorization code delivered in the URI request parameter through an HTTP 302 redirect. This redirect causes the browser to make a request to the client, including the authorization code:

```
GET /callback?code=SyWhvRM2&state=Lwt50DDQKUB8U7jtfLQCVGDL9cnmwHH1 HTTP/1.1
Host: localhost:9000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:39.0)
Gecko/20100101 Firefox/39.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer:
http://localhost:9001/authorize?response_type=code&scope=foo&client_id=oauthclient-
1&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcallback&state=Lwt50DDQ
KUB8U7jtfLQCVGDL9cnmwHH1
Connection: keep-alive
```

The value of the authorization code is a one-time-use credential and it represents the result of the resource owner’s authorization decision. We want to highlight that for confidential clients the authorization code leaves the server and passes through the user agent, hence it will persist in the browser history.

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/CommonAuthoriza%20tionServerVulnerabilities/Images/casv1.PNG" />

Let’s consider the following scenario. Imagine there is a web server, let’s call it Site A, that consumes some REST APIs as an OAuth client. A resource owner accesses Site A in a library or some other location with a shared computer. Site A uses the authorization code grant (see chapter 2 for details) to get its OAuth tokens. This will imply that a login to the authorization server is required. As a result of using the site, the authorization code will remain in the browser history (as seen in figure 9.1). When the resource owner finishes, they will almost certainly log out of Site A, and might even log out of the authorization server, but they won’t likely clean their browser history. At this stage, an attacker that also uses Site A will get on the computer. The attacker will log in with their own credentials but will tamper with the redirect to Site A and inject the authorization code from the previous resource owner’s session stored in the browser history. What will happen is that, despite the fact the attacker is logged in with their own credentials, they will have access to the resource of the original resource owner.

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/CommonAuthoriza%20tionServerVulnerabilities/Images/casv2.PNG" />

It turns out that the OAuth core specification1 gives us a solution to this problem in section 4.1.3:

```
The client MUST NOT use the authorization code more than once. If an authorization code is used more than once, the authorization server MUST deny the request and SHOULD revoke (when possible) all tokens previously issued based on that authorization code.
```

It is up to the implementer to follow and implement the specification correctly. In chapter 5, the authorizationServer.js that you built does follow this advice.

Another protection for the authorization code grant type is to bind the authorization code to the client_id, particularly for authenticated clients. In our code base, this is done in the next line:

```js
if (code.authorizationEndpointRequest.client_id == clientId) {
```

This is needed in order to cover one of the other bullets in section 4.1.3 of RFC 6749:

```
ensure that the authorization code was issued to the authenticated confidential client, or if the client is public, ensure that the code was issued to “client_id” in the request,
```

## Client impersonation

All the techniques we’ve seen used to steal the authorization code were related to some sort of `redirect_uri` manipulation.

The registered `redirect_uri` didn’t exactly match the one provided in the OAuth request. Nevertheless, the attacker hijacked the authorization code though a maliciously crafted URI.

Now what an attacker can do is to present this hijacked authorization code to the OAuth callback of the victim’s OAuth client. At this point, the client will proceed and try to trade the authorization code for an access token, presenting valid client credentials to the authorization server. The authorization code is bound to the correct OAuth client.

The result is that the attacker is able to successfully consume the hijacked authorization code and steal the protected resource of a target victim.

Let’s see how we can fix this in our code base.

In the file, locate the authorization server’s token endpoint and specifically the part that processes authorization grant request, then add the following snippet of code:

```js
if (code.request.redirect_uri) {
  if (code.request.redirect_uri != req.body.redirect_uri) {
    res.status(400).json({error: ‘invalid_grant’});
    return;
  }
}
```

When the OAuth client presents the hijacked authorization code to the authorization server, the authorization server will now ensure that the redirect_uri presented in the initial authorization request will match the one presented in the token request. Since the client isn’t expecting to send anyone to the attacker’s site, these values will never match and the attack fails. Having this simple check in place is extremely important and can negate many common attacks on the authorization code grant.
