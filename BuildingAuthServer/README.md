[index](https://github.com/KiraDiShira/OAuth2/blob/master/README.md#oauth2)

# Building a simple OAuth authorization server

It is the central security authority throughout a given OAuth system. Only the authorization server can authenticate users, register clients, and issue tokens. During the development of the OAuth 2.0 specifications, wherever possible complexity was pushed onto the authorization server from the client or the protected resource. This is largely due to the arity of the components: there are many more clients than protected resources, and many more protected resources than authorization servers.

The authorization server is required to have two endpoints in the OAuth protocol: 
- the authorization endpoint, which serves **front-channel** interactions: `app.get("/authorize", function(req, res){` 
- the token endpoint, which serves **back-channel** interactions: `app.post("/token", function(req, res){` 
