[index](https://github.com/KiraDiShira/OAuth2/blob/master/README.md#oauth2)

# Common OAuth token vulnerabilities

## What is a bearer token?

One choice made by the OAuth working group while designing the OAuth 2.0 specification was to drop the custom signature mechanism present in the original OAuth 1.0 specification in favor of relying on secure transport-layer mechanisms, such as TLS, between parties. By removing the signing requirement from the base protocol, OAuth 2.0 can accommodate different kinds of tokens. The OAuth specification defines a bearer token as a security device with the property that any party in possession of the token (a “bearer”) can use the token, regardless of who that party is. In this way, a bearer token is much like a bus token. As long as you’ve got a bus token, you can ride the bus.

From a technological standpoint, you can think about bearer tokens in much the same way as you do browser cookies. Both share some basic properties:

- They use plaintext strings.
- No secret or signature is involved.
- TLS is the basis of the security model.

But there are some differences:

- Browsers have a long history of dealing with cookies, whereas OAuth clients don’t.
- Browsers enforce the same origin policy, meaning that a cookie for one domain isn’t passed to another domain. This isn’t the case for OAuth clients (and may be a source of problems).

## Risks and considerations of using bearer tokens

Apart from token hijacking (which we’ve covered in depth in many parts of this book), the following threats associated with OAuth’s bearer tokens are common to many other token-based protocols:

**Token forgery**. An attacker may manufacture its own bogus token or modify an existing valid one, causing the resource server to grant inappropriate access to the client. For example, an attacker can craft a token to gain access to information they weren’t able to view before. Alternatively, an attacker could modify the token and extend the validity of the token itself.

**Token replay**. An attacker attempts to use an old token that was already used in the past and is supposed to be expired. The resource server shouldn’t return any valid data in this case; instead, it should return an error. In a concrete scenario, an attacker legitimately obtains an access token in the first place and they’ll try to reuse it long after the token has expired.

**Token redirect**. An attacker uses a token generated for consumption by one resource server to gain access to a different resource server that mistakenly believes the token to be valid for it. In this case, an attacker legitimately obtains an access token for a specific resource server and they try to present this access token to a different one.

**Token disclosure**. A token might contain sensitive information about the system and the attacker is then something that they couldn’t know otherwise. Information disclosure can be considered a minor problem compared with the previous one, but it’s still something we need to care about.
