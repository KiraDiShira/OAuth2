[index](https://github.com/KiraDiShira/OAuth2/blob/master/README.md#oauth2)

# OAuth tokens

- [What are OAuth tokens?](#what-are-oauth-tokens)
- [Structured tokens: JSON Web Token (JWT)](#structured-tokens-json-web-token-jwt)
- [Cryptographic protection of tokens: JSON Object Signing and Encryption (JOSE)](#cryptographic-protection-of-tokens-json-object-signing-and-encryption-jose)

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

## Cryptographic protection of tokens: JSON Object Signing and Encryption (JOSE)

If the authorization server outputs a token that is not protected in any way, and the protected resource trusts what’s inside that token without any other checks, then it’s trivial for the client, which receives the token in plain text, to manipulate the content of the token before presenting it to the protected resource. A client could even make up its own token out of whole cloth without ever talking to the authorization server, and a naïve resource server would simply accept and process it.

Since we almost certainly do not want that to happen, we should add some protection to this token. Thankfully for us, there’s a whole suite of specifications that tell us exactly how to do this: the **JSON Object Signing and Encryption standards**, or **JOSE**.

This suite provides signatures (JSON Web Signatures, or **JWS**), encryption (JSON Web Encryption, or **JWE**), and even key storage formats (JSON Web Keys, or **JWK**) using JSON as the base data model. The unsigned JWT that we built by hand in the last section is merely a special case of an unsigned JWS object with a JSON-based payload. 

Although the details of JOSE could fill a book on its own, we’re going to look at two common cases: symmetric signing and validation using the HMAC signature scheme and asymmetric signing and validation using the RSA signature scheme. We’ll also be using JWK to store our public and private RSA keys.

To do the heavy cryptographic lifting, we’re going to be using a JOSE library called JSRSASign. This library provides basic signing and key management capabilities, but it doesn’t provide encryption. We’ll leave encrypted tokens as an exercise for the reader.

### Symmetric signatures using HS256

We’re going to sign our token using a shared secret at the authorization server and then validate that token using the shared secret at the protected resource.

**authorizationServer.js**
```js
var header = { 'typ': 'JWT', 'alg': 'HS256'};
```

This time, instead of concatenating the strings together with dots, we’re going to use our JOSE library to apply the HMAC signature algorithm, using our shared secret, to the token. Due to a quirk in our chosen JOSE library, we need to pass in the shared secret as a hex string; other libraries will have different requirements for getting the keys in the right format. The output of the library will be a string that we’ll use as the token value.

```js
var access_token = jose.jws.JWS.sign(header.alg, JSON.stringify(header), JSON.stringify(payload), new Buffer(sharedTokenSecret).toString('hex')); 
```

The final JWT looks something like the following:

```js
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDEv
Iiwic3ViIjoiOVhFMy1KSTM0LTAwMTMyQSIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMi
8iLCJpYXQiOjE0NjcyNTEwNzMsImV4cCI6MTQ2NzI1MTM3MywianRpIjoiaEZLUUpSNmUifQ.
WqRsY03pYwuJTx-9pDQXftkcj7YbRn95o-16NHrVugg
```

The rest of the server remains unchanged, as we’re still storing the token in the database. However, if we wanted to, we could remove the storage requirement on our authorization server entirely because the token is recognizable by the server from its signature.

Once again, our client is none the wiser that the token format has changed. However, we’re going to need to edit the protected resource so that it can check the token’s signature. To do this, open protectedResource.js and note the same random secret string at the top of the file. Once again, in a production environment, this is likely handled through a key management process and the secret isn’t likely to be this simple to type.

First we need to parse the token, but that’s pretty much like last time.

```js
var tokenParts = inToken.split('.');
var header = JSON.parse(base64url.decode(tokenParts[0]));
var payload = JSON.parse(base64url.decode(tokenParts[1]));
```
Next, verify the signature based on our shared secret, and that will be our first check of the token’s contents. Remember, our library needs the secret to be converted to hex before it can validate things.

All of the previous token validity checks go inside this if statement:

```js
if (jose.jws.JWS.verify(inToken, new Buffer(sharedTokenSecret).toString('hex'), [header.alg])) {

}
```

Only if the signature is valid do we parse the JWT and check its contents for consistency. If all checks pass, we can hand it off to the application, as we did previously. Now the resource server will only accept tokens that have been signed by the secret that it shares with the authorization server.

### Asymmetric signatures using RS256

We’re once again going to sign the token with a secret key, as we did in the last section. However, this time, we’re going to use public key cryptography to do it. With a shared secret, both systems need the same key either to create or to validate the signature. This effectively means that either the authorization server or the resource server could create the tokens in the last exercise, because they both had access to the keying material needed to do so. With public key cryptography, the authorization server has both a private key and a public key that it can use to generate tokens, whereas the protected resource needs to be able to access only the authorization server’s public key to verify the token. Unlike with a shared secret, the protected resource has no way of generating its own valid tokens even though it can easily verify them. We’re going to be using the RS256 signature method from JOSE, which uses the RSA algorithm under the hood.

First, we need to add a public and private key pair to our authorization server. Our key pair is a 2048-bit RSA key, which is the minimum recommended size. We’re using keys stored in the JSON-based JWK format for this exercise, and they can be read natively by our
library.

```js
var rsaKey = {
  "alg": "RS256",
  "d": "ZXFizvaQ0RzWRbMExStaS_-yVnjtSQ9YslYQF1kkuIoTwFuiEQ2OywBfuyXhTvVQxIiJqPNnUyZR6kXAhyj__wS_Px1EH8zv7BHVt1N5TjJGlubt1dhAFCZQmgz0D-PfmATdf6KLL4HIijGrE8iYOPYIPF_FL8ddaxx5rsziRRnkRMX_fIHxuSQVCe401hSS3QBZOgwVdWEb1JuODT7KUk7xPpMTw5RYCeUoCYTRQ_KO8_NQMURi3GLvbgQGQgk7fmDcug3MwutmWbpe58GoSCkmExUS0U-KEkHtFiC8L6fN2jXh1whPeRCa9eoIK8nsIY05gnLKxXTn5-aPQzSy6Q",
  "e": "AQAB",
  "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
  "kty": "RSA",
  "kid": "authserver"
};
```

This key pair was randomly generated, and in a production environment you’ll want to have a unique key for each service.

First we need to indicate that our token is signed with the RS256 algorithm. We’re also going to indicate that we’re using the key with the key ID (kid) of authserver from our authorization server. The authorization server may have only one key right now, but if you were to add other keys to this set, you’d want the resource server to be able to know which one you used.

```js
var header = { 'typ': 'JWT', 'alg': rsaKey.alg, 'kid': rsaKey.kid };
```

Next, we need to convert our JWK-formatted key pair into a form that our library can use for cryptographic operations. Thankfully, our library gives us a simple utility for doing that.7 We can then use this key to sign the token.

```js
var privateKey = jose.KEYUTIL.getKey(rsaKey);
```

Then we’ll create our access token string much like we did before, except this time we use our private key and the RS256 asymmetric signing algorithm.

```js
var access_token = jose.jws.JWS.sign(header.alg,
JSON.stringify(header),
JSON.stringify(payload),
privateKey);
```

The result is the token similar to the previous one, but it’s now been signed asymmetrically.

```js
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImF1dGhzZXJ2ZXIifQ.eyJpc3MiOiJodH
RwOi8vbG9jYWxob3N0OjkwMDEvIiwic3ViIjoiOVhFMy1KSTM0LTAwMTMyQSIsImF1ZCI6Imh
0dHA6Ly9sb2NhbGhvc3Q6OTAwMi8iLCJpYXQiOjE0NjcyNTE5NjksImV4cCI6MTQ2NzI1MjI2
OSwianRpIjoidURYMWNwVnYifQ.nK-tYidfd6IHW8iwJ1ZHcPPnbDdbjnveunKrpOihEb0JD5w
fjXoYjpToXKfaSFPdpgbhy4ocnRAfKfX6tQfJuFQpZpKmtFG8OVtWpiOYlH4Ecoh3soSkaQyIy
4L6p8o3gmgl9iyjLQj4B7Anfe6rwQlIQi79WTQwE9bd3tgqic5cPBFtPLqRJQluvjZerkSdUo
7Kt8XdyGyfTAiyrsWoD1H0WGJm6IodTmSUOH7L08k-mGhUHmSkOgwGddrxLwLcMWWQ6ohmXa
Vv_Vf-9yTC2STHOKuuUm2w_cRE1sF7JryiO7aFRa8JGEoUff2moaEuLG88weOT_S2EQBhYB
0vQ8A
```

The client once again remains unchanged, but we do have to tell the protected resource how to validate the signature of this new JWT. Open up protectedResource.js so that we can tell it the server’s public key.

```js
var rsaKey = {
  "alg": "RS256",
  "e": "AQAB",
  "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_
YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81
YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5
to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxV
tAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
  "kty": "RSA",
  "kid": "authserver"
};
```

This data is from the same key pair as the one in the authorization server, but it doesn’t contain the private key information (represented by the d element in an RSA key). The effect is that the protected resource can only verify incoming signed JWTs, but it cannot create them.

**Do I have to copy my keys all over the place?**
`
You might think it’s onerous to copy signing and verification keys between pieces of software like this, and you’d be right. If the authorization server ever decides to update its keys, all copies of the corresponding public key need to be updated in all protected resources downstream. For a large OAuth ecosystem, that can be problematic.

One common approach, used by the OpenID Connect protocol that we’ll cover in chapter 13, is to have the authorization server publish its public key at a known URL. This will generally take the form of a JWK Set, which can contain multiple keys and looks something like this.`

```js
{
  "keys": [
    {
      "alg": "RS256",
      "e": "AQAB",
      "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_
COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-Bkqww
WL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-
ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f
0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
      "kty": "RSA",
      "kid": "authserver"
    }
  ]
}
```
`The protected resources can then fetch and cache this key as needed. This approach allows the authorization server to rotate its keys whenever it sees fit, or add new keys over time, and the changes will automatically propagate throughout the network.`

Now we’ll use our library to validate the signatures of incoming tokens based on the server’s public key. Load up the public key into an object that our library can use, and then use that key to validate the token’s signature.

```js
var publicKey = jose.KEYUTIL.getKey(rsaKey);

if (jose.jws.JWS.verify(inToken, publicKey, [header.alg])) {
}
```

Now that this has been set up, the authorization server can choose to include additional information for the protected resource’s consumption, such as scopes or client identifiers.
