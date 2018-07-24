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
