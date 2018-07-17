[index](https://github.com/KiraDiShira/OAuth2/blob/master/README.md#oauth2)

# Common client vulnerabilities

- [CSRF attack against the client](#csrf-attack-against-the-client)
- [Theft of client credentials](#theft-of-client-credentials)
- [Registration of the redirect URI](#registration-of-the-redirect-uri)

## CSRF attack against the client

Both the authorization code and the implicit grant types mention a recommended state parameter. This parameter is:

```
An opaque value used by the client to maintain state between the request and callback. The authorization server includes this value when redirecting the user-agent back to the client. The parameter SHOULD be used for preventing cross-site request forgery (CSRF).
```

CSRF occurs when a malicious application causes the user’s browser to perform an unwanted action through a request to a web site where the user is currently authenticated.

How is that possible? The main thing to keep in mind is that browsers make requests (with cookies) to any origin, allowing specific actions to be performed when requested. If a user is logged in to one site that offers the capability to execute some sort of task and an attacker tricks the user’s browser into making a request to one of these task URIs, then the task is performed as the logged-in user. Typically, an attacker will embed malicious HTML or JavaScript code into an email or website to request a specific task URI that executes without the user’s knowledge.

The most common and effective mitigation is to add an unpredictable element in each HTTP request, which is the countermeasure taken by the OAuth specification. Let’s see why the use of the state parameter is highly encouraged to avoid CSRF and how to produce a proper state parameter to be safely used.

Let’s assume there is an OAuth client that supports the authorization code grant type. When the OAuth client receives a code parameter on its OAuth callback endpoint, it then will trade the received code for an access token. Eventually, the access token is passed to the resource server when the client calls an API on behalf of the resource owner. To perform the attack, the attacker can simply start an OAuth flow and get an authorization code from the target authorization server, stopping his “OAuth dance” here. The attacker causes the victim’s client to “consume” the attacker’s authorization code. The latter is achieved by creating a malicious page in his website, something like:

```
<img src="https://ouauthclient.com/callback?code=ATTACKER_AUTHORIZATION_CODE">
```

and convince the victim to visit it.

This would have the net effect of the resource owner having his client application connected with the attacker’s authorization context. This has disastrous consequences when the OAuth protocol is used for authentication, which is further discussed in chapter 13.

The mitigation for an OAuth client is to generate an unguessable state parameter and pass it along to the first call to the authorization server. The authorization server is required by the specification to return this value as-is as one of the parameters to the redirect URI. Then when the redirect URI is called, the client checks the value of the state parameter. If it is absent or if it doesn’t match the value originally passed, the client can terminate the flow with an error. This prevents an attacker from using their own authorization code and injecting it into an unsuspecting victim’s client. 

One natural question that can easily arise is what this state parameter should look like. The specification doesn’t help too much because it’s pretty vague:

```
The probability of an attacker guessing generated tokens (and other credentials not intended for handling by end-users) MUST be less than or equal to 2 -128 and SHOULD be less than or equal to 2 -160.
```

The generated state value can then be stored either in the cookie or, more appropriately, in the session and used subsequently to perform the check as explained earlier.

Although the use of state isn’t explicitly enforced by the specification, it is considered best practice and its presence is needed to defend against CSRF.

https://auth0.com/blog/ten-things-you-should-know-about-tokens-and-cookies/

## Theft of client credentials

The OAuth core specification specifies four different grant types. Each grant type is designed with different security and deployment aspects in mind and should be used accordingly, as discussed in chapter 6. For example, the implicit grant flow is to be used by OAuth clients where the client code executes within the user agent environment. Such clients are generally JavaScript-only applications, which have, of course, limited capability of hiding the client_secret in client side code running in the browser. On the other side of the fence there are classic server-side applications that can use the authorization code grant type and can safely store the client_secret somewhere in the server.

What about native applications? We have already seen in chapter 6 when to use which grant type, and as a reminder it isn’t recommended that native applications use the implicit flow. It is important to understand that for a native application, even if the client_secret is somehow hidden in the compiled code it must not be considered as a secret. Even the most arcane artifact can be decompiled and the client_secret is then no longer that secret. The same principle applies to mobile clients and desktop native applications.

In chapter 12 we’re going to discuss in detail how to use dynamic client registration to configure the client_secret at runtime.

Client_id and client_secret parts are empty.

```js
var client = {
  'client_name': 'Native OAuth Client',
  'client_id': '',
  'client_secret': '',
  'redirect_uris': ['com.oauthinaction.mynativeapp:/'],
  'scope': 'foo bar'
};
```

This information will be available at runtime after the dynamic registration phase is concluded. Now locate the authorization server information and add the registrationEndpoint.

```js
var authServer = {
  authorizationEndpoint: 'http://localhost:9001/authorize',
  tokenEndpoint: 'http://localhost:9001/token',
  registrationEndpoint: 'http://localhost:9001/register'
};
```

Finally, we need to plug the dynamic registration request when the application first requests an OAuth token, if it doesn’t already have a client ID.

```js
if (!client.client_id) {
  $.ajax({
       url: authServer.registrationEndpoint,
       type: 'POST',
       data: client,
       crossDomain: true,
       dataType: 'json'
   }).done(function(data) {
        client.client_id = data.client_id;
        client.client_secret = data.client_secret;
   }).fail(function() {
        $('.oauth-protected-resource').text('Error while fetching registration endpoint');
});
```
We’re now ready to run our modified native application If you start the usual OAuth flow, you can now appreciate that both the client_id and client_secret have been freshly generated, and these will be different for any instance of the native application. This will solve the issue of having the client_secret shipped with the native application artifact. A production instance of such a native application would, of course, store this information so that each installation of the client software will register itself once on startup, but not every time the user launches it. No two instances of the client application will have access to each other’s credentials, and the authorization server can differentiate between instances.

## Registration of the redirect URI

If you’re not careful with `redirect_uri` registration requirements, token hijacking attacks become significantly easier than you might think.

The main reason behind this is that sometimes authorization servers use different redirect_uri validation policies. As we’ll see in chapter 9, the only reliably safe validation method the authorization server should adopt is exact matching. All the other potential solutions, based on regular expressions or allowing subdirectories of the registered redirect_uri, are suboptimal and sometimes even dangerous.

<img src="" />
