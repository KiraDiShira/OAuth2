# Common client vulnerabilities

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