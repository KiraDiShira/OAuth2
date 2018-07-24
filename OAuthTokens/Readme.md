[index](https://github.com/KiraDiShira/OAuth2/blob/master/README.md#oauth2)

# OAuth tokens

- [What are OAuth tokens?](#what-are-oauth-tokens)

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
