[index](https://github.com/KiraDiShira/OAuth2/blob/master/README.md#oauth2)

# OAuth tokens

- [What are OAuth tokens?](#what-are-oauth-tokens)
- [Structured tokens: JSON Web Token (JWT)](#structured-tokens-json-web-token-jwt)

## What are OAuth tokens?

OAuth makes absolutely no mention about what the content of a token is.

By not specifying the tokens themselves, OAuth can be used in a wide variety of deployments with different characteristics, risk profiles, and requirements. OAuth tokens can expire, or be revocable, or be indefinite, or be some combination of these depending on circumstances. They can represent specific users, or all users in a system, or no users at all. They can have an internal structure, or be random nonsense, or be cryptographically protected, or even be some combination of these options. This flexibility and modularity allows OAuth to be adapted in ways that are difficult for more comprehensive security protocols such as WS-*, SAML, and Kerberos that do specify the token format and require all parties in the system to understand it.

We created tokens that were random blobs of alphanumeric characters:

```
s9nR4qv7qVadTUssVD5DqA7oRLJ2xonn
```

When the authorization server created the token, it stored the token’s value in a shared database on disk. When the protected resource received a token from the client, it looked up the token’s value in that same database to figure out what the token was good for. These tokens carry no information inside of them and instead act as simple handles for data lookup. This is a perfectly valid and not uncommon method of creating and managing access tokens, and it has the benefit of being able to keep the token itself small while still providing a large amount of entropy.

It’s not always practical to share a database between the authorization server and protected resource, especially when a single authorization server is protecting several different protected resources downstream. What then can we do instead? We’re going to look at two other common options in this chapter: structured tokens and token introspection.

## Structured tokens: JSON Web Token (JWT)

Instead of requiring a lookup into a shared database, what if we could create a token that had all of the necessary information inside of it? 

This way, an authorization server can communicate to a protected resource indirectly through the token itself, without any use of a network API call.

With this method, the authorization server packs in whatever information the protected resource will need to know, such as the expiration timestamp of the token and the user who authorized it. All of this gets sent to the client, but the client doesn’t notice it because the token remains opaque to the client in all OAuth 2.0 systems. 

Once the client has the token, it sends the token to the protected resource as it would a random blob. The protected resource, which does need to understand the token, parses the information contained in the token and makes its authorization decisions based on that. 

### The structure of a JWT

At its core, a JWT is a JSON object that’s wrapped into a format for transmission across the wire. The simplest form of JWT, an unsigned token, looks something like this:

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
```

There are two sections of characters separated by single periods. Each of these is a different part of the token, and if we split the token string on the dot character, we can process the sections separately.

Each value between the dots isn’t random but is a, Base64 encoding with a URL-safe alphabet and no padding characters, JSON object.

If we decode the Base64 and parse the JSON object inside the first section, we get a simple object.

```
{
  "typ": "JWT",
  "alg": "none"
}
```

This header is always a JSON object and it’s used to describe information about the rest of the token. The `typ` header tells the application processing the rest of the token what to expect in the second section, the payload. In our example, we’re told that it’s a JWT. 

Although there are other data containers that can use this same structure, JWT is far and away the most common and the best fit for our purposes as an OAuth token. This also includes the `alg header` with the special value none to indicate that this is an unsigned token. 

The second section is the payload of the token itself, and it’s serialized in the same way as the header: Base64URL-encoded JSON. Because this is a JWT, the payload can be any JSON object, and in our previous example it’s a simple set of user data.

```
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

**Why Base64?**
After all, it’s not human readable and it requires extra processing steps to make sense of it. Wouldn’t it be better to use JSON directly? 

Part of the answer comes from the places where a JWT will typically find itself: in HTTP headers, query parameters, form parameters, and strings in various databases and programming languages. Each of these locations tends to have a limited set of characters that can be used without additional encoding. 

For example, in order to send a JSON object over an HTTP form parameter, the opening and closing brackets { and } would need to be encoded as %7B and %7D, respectively. Quotation marks, colons, and other common characters would also need to be encoded to their appropriate entity codes. Even something as common as the space character could be encoded as either %20 or +, depending on the location of the token. Additionally, in many cases, the % character used for encoding itself needs to be encoded, often leading to accidental double-encoding of the values.

By natively using the Base64URL encoding scheme, JWT can be placed safely in any of these common locations without any additional encoding. Furthermore, since the JSON objects are coming through as an encoded string, they’re less likely to be processed and reserialized by processing middleware, which we’ll see is important in the next section. This kind of transportation-resistant armor is attractive to deployments and developers, and it’s helped JWT find a foothold where other security token formats have faltered.

### JWT claims

In addition to a general data structure, JWT also gives us a set of **claims** for use across different applications. Although a JWT can contain any valid JSON data, these claims provide support for common operations that involve these kinds of tokens. All of these fields are optional in a JWT, but specific services are allowed to define their own inclusion requirements.

We can also add any additional fields that we need for our specific application. In our previous example token, we’ve added the name and admin fields to the payload.

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/OAuthTokens/Images/ot1.PNG" />

### Implementing JWT in our servers

In chapter 5 we created a server that issued unstructured, randomized tokens. We’ll be modifying the server to produce unsigned JWT formatted tokens here. 

Although we do recommend using a JWT library in practice, we’ll be producing our JWTs by hand so that you can get a feel for what goes into these tokens.

Starting by commenting out (or deleting) the following line:

```js
var access_token = randomstring.generate();
```

We’re going to indicate that this token is a JWT and that it’s unsigned.

```js
var header = { 'typ': 'JWT', 'alg': 'none' };
```

```js
var payload = {
  iss: 'http://localhost:9001/',
  sub: code.user ? code.user.sub : undefined,
  aud: 'http://localhost:9002/',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + (5 * 60),
  jti: randomstring.generate(8)
};
```

```js
var access_token = base64url.encode(JSON.stringify(header))
+ '.'
+ base64url.encode(JSON.stringify(payload))
+ '.';
```

Notice that our token now has an expiration associated with it, but the client doesn’t have to do anything special with that change. The client can keep using the token until it stops working, at which point the client will go get another token as usual. The authorization server is allowed to provide an expiration hint to the client using the `expires_in` field of the token response, but the client doesn’t even have to do anything with that either, and most clients don’t.

Now it’s time to have our protected resource check the incoming token for its information instead of looking up the token value in a database. Open up protectedResource. js and find the code that processes the incoming token. First we need to parse the token by performing the opposite actions that the authorization server used to create it: we split it on the dot characters to get the different sections. Then we’ll decode the second part, the payload, from Base64 URL and parse the result as a JSON object.

```js
var tokenParts = inToken.split('.');
var payload = JSON.parse(base64url.decode(tokenParts[1]));
```

This gives us a native data structure that we can check in our application. We’re going to make sure that the token is coming from the expected issuer, that its timestamps fit the right ranges, and that our resource server is the intended audience of the token. Although these kinds of checks are often strung together with boolean logic, we’ve broken these out into individual if statements so that each check can be read more clearly and independently.

```js
if (payload.iss == 'http://localhost:9001/') {
  if ((Array.isArray(payload.aud) && __.contains(payload.aud, 'http://localhost:9002/')) ||
    payload.aud == 'http://localhost:9002/') {
      var now = Math.floor(Date.now() / 1000);
      if (payload.iat <= now) {
        if (payload.exp >= now) {
          req.access_token = payload;
        }
      }
  }
}
```
If all of those checks pass, we’ll hand the token’s parsed payload on to the rest of the application, which can make authorization decisions based on fields such as the subject, if it so chooses.

Remember, the payload of a JWT is a JSON object, which our protected resource can now access directly from the request object. From here it’s up to the other handler functions to determine whether this particular token is good enough to serve the requests in question, as we did when the token was stored in the shared database.

The attributes included in the token’s body in our example don’t say that much, but we could easily include information about the client, resource owner, scopes, or other information pertinent to the protected resource’s decision.

We haven’t had to change our client code at all, even though the tokens that are being issued are different from what were being issued before. This is all thanks to the tokens being opaque to the client, which is a key simplifying factor in OAuth 2.0. In fact, the authorization server could have picked many different kinds of token formats without any change to the client software.
It’s good that we can now carry information in the token itself, but is that enough?
