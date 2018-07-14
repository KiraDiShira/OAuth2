[index](https://github.com/KiraDiShira/OAuth2/blob/master/README.md#oauth2)

# OAuth 2.0 in the real world

One of the key areas that OAuth 2.0 can vary is that of the **authorization grant**, colloquially known as the **OAuth flow**.

## Implicit grant type

One key aspect of the different steps in the authorization code flow is that it keeps information separate between different components. This way, the browser doesn’t learn things that only the client should know about, and the client doesn’t get to see the state of the browser, and so on. But what if we were to put the client inside the browser?

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/OAuth2RealWorld/Images/rw1.PNG" />

The client then can’t keep any secrets from the browser, which has full insight
into the client’s execution. In this case, there is no real benefit in passing the authorization
code through the browser to the client, only to have the client exchange that
for a token because the extra layer of secrets isn’t protected against anyone involved.
The implicit grant type does away with this extra secret and its attendant round trip by
returning the token directly from the authorization endpoint. The implicit grant type
therefore uses only the front channel2 to communicate with the authorization server.
This flow is very useful for JavaScript applications embedded within websites that need
to be able to perform an authorized, and potentially limited, session sharing across
security domains.
The implicit grant has severe limitations that need to be considered when approaching
it. First, there is no realistic way for a client using this flow to keep a client secret,
since the secret will be made available to the browser itself. Since this flow uses only the
authorization endpoint and not the token endpoint, this limitation does not affect its ability to function, as the client is never expected to authenticate at the authorization
endpoint. However, the lack of any means of authenticating the client does impact the
security profile of the grant type and it should be approached with caution. Additionally,
the implicit flow can’t be used to get a refresh token. Since in-browser applications
are by nature short lived, lasting only the session length of the browser context that has
loaded them, the usefulness of a refresh token would be very limited. Furthermore,
unlike other grant types, the resource owner can be assumed to be still present in the
browser and available to reauthorize the client if necessary.

The client sends its request to the authorization server’s authorization endpoint in
the same manner as the authorization code flow, except that this time the response_
type parameter is set to `token` instead of `code`.

the browser makes a request to the authorization
server’s authorization endpoint. The resource owner authenticates themselves and authorizes the client in the same manner as the authorization code flow. However,
this time the authorization server generates the token immediately and returns it by
attaching it to the URI fragment of the response from the authorization endpoint.
Remember, since this is the front channel, the response to the client comes in the form
of an HTTP redirect back to the client’s redirect URI.

```
GET /callback#access_token=987tghjkiu6trfghjuytrghj&token_type=Bearer
HTTP/1.1
Host: localhost:9000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:39.0)
Gecko/20100101 Firefox/39.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer: http://localhost:9001/authorize?response_type=code&scope=foo&client_
id=oauth-client-1&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcallback&state
=Lwt50DDQKUB8U7jtfLQCVGDL9cnmwHH1
```

The fragment portion of the URI isn’t usually sent back to the server, which means that the token value itself is available only inside the browser. Note, however, that this behavior does vary depending on the browser implementation and version.
