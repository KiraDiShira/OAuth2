[index](https://github.com/KiraDiShira/OAuth2/blob/master/README.md#oauth2)

## Authorization code grant

There are two major steps to an OAuth transaction: issuing a token and using a token.

We’ll be following the **authorization code grant**.

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/OAuthDance/Images/od4.PNG" />

First, the resource owner goes to the client application and indicates to the client that they would like it to use a particular protected resource on their behalf. For instance, this is where the user would tell the
printing service to use a specific photo storage service. This service is an API that the client knows how to process, and the client knows that it needs to use OAuth to do so.

When the client realizes that it needs to get a new OAuth access token, it sends the resource owner to the authorization server with a request that indicates that the client is asking to be delegated some piece of authority by that resource owner (figure 2.2). For example, our photo printer could ask the photo-storage service for the ability to read the photos stored there.

Since we have a web client, this takes the form of an **HTTP redirect** to the authorization server’s authorization endpoint.

The client identifies itself and requests particular items such as scopes by including query parameters in the URL it sends the user to. The authorization server can parse those parameters and act accordingly, even though the client isn’t making the request directly.

Next, the authorization server will usually require the user to authenticate. This step is essential in determining who the resource owner is and what rights they’re allowed to delegate to the client. The user’s authentication passes directly between the user (and their browser) and the authorization server; it’s never seen by the client application. This essential aspect protects the user from having to share their credentials with the client application, the antipattern that OAuth was invented to combat (as discussed in the last chapter). Additionally, since the resource owner interacts with the authorization endpoint through a browser, their authentication happens through a browser as well. Thus, a wide variety of authentication techniques are available to the user authentication process. OAuth doesn’t dictate the authentication technology, and the authorization server is free to choose methods such as a username/password pair, cryptographic certificates, security tokens, federated single-sign-on, or any number of other possibilities.

Next, the user authorizes the client application (figure 2.4). In this step, the resource owner chooses to delegate some portion of their authority to the client application, and the authorization server has many different options to make this work. The client’s request can include an indication of what kind of access it’s looking for (known as the OAuth scope, discussed in section 2.4). The authorization server can allow the user to deny some or all of these scopes, or it can let the user approve or deny the request as a whole.

Next, the authorization server **redirects** the user back to the client application. Since we’re using the authorization code grant type, this redirect includes the special code query parameter. The value of this parameter is a one-time-use credential known as the authorization code, and it represents the result of the user’s authorization decision. The client can parse this parameter to get the authorization code value when the request comes in, and it will use that code in the next step. The client will also check that the value of the **state parameter** matches the value that it sent in the previous step.

Now that the client has the code, it can send it back to the authorization server on its token endpoint. The client performs an HTTP POST with its parameters as a form-encoded HTTP entity body, passing its client_id and client_secret as an HTTP Basic authorization header. This HTTP request is made directly between the client and the authorization server, without involving the browser or resource owner at all.

The authorization server takes in this request and, if valid, issues a token (figure 2.7). The authorization server performs a number of steps to ensure the request is legitimate. First, it validates the client’s credentials (passed in the Authorization header here) to determine which client is requesting access. Then, it reads the value of the code parameter from the body and looks up any information it has about that authorization code, including which client made the initial authorization request, which user authorized it, and what it was authorized for. If the authorization code is valid, has not been used previously, and the client making this request is the same as the client that made the original request, the authorization server generates and returns a new access
token for the client. This token is returned in the HTTP response as a JSON object.

The client can now parse the token response and get the access token value from it to be used at the protected resource. In this case, we have an OAuth Bearer token, as indicated by the token_type field in the response. The response can also include a refresh token (used to get new access tokens without asking for authorization again) as well as additional information about the access token, like a hint about the token’s scopes and expiration time. The client can store this access token in a secure place for as long as it wants to use the token, even after the user has left.

With the token in hand, the client can present the token to the protected resource (see figure 2.8). The client has several methods for presenting the access token, and in this example we’re going to use the recommended method of using the Authorization header.

The protected resource can then parse the token out of the header, determine whether it’s still valid, look up information regarding who authorized it and what it was authorized for, and return the response accordingly.

## Refresh tokens

An OAuth refresh token is similar in concept to the access token, in that it’s issued to the client by the authorization server and the client doesn’t know or care what’s inside the token. What’s different, though, is that the token is never sent to the protected resource. Instead, the client uses the refresh token to request new access tokens without involving the resource owner

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/OAuthDance/Images/od1.PNG" />

Why would a client need to bother with a refresh token? In OAuth, an access token could stop working for a client at any point. The user could have revoked the token, the token could have expired, or some other system trigger made the token invalid. The client will usually find out about the token being invalid by using it and receiving an error response. Of course, the client could have the resource owner authorize it again, but what if the resource owner’s no longer there?

In OAuth 2.0, access tokens were given the option to expire automatically, but we still need a way to access resources when the user was
no longer there. The refresh token now takes the place of the long-lived token, but instead of it being used to obtain resources, it’s used only to get new access tokens that, in turn, can get the resources. This limits the exposure of the refresh token and the access token in separate but complementary ways. Refresh tokens also give the client the ability to down-scope its access. If a client is granted scopes A, B, and C, but it knows that it needs only scope A to make a particular call, it can use the refresh token to request an access token for only scope A. This lets a smart client follow the security principle of least privilege without burdening less-smart clients with trying to figure out what privileges an API needs.

What then if the refresh token itself doesn’t work? The client can always bother the resource owner again, when they’re available. In other words, the fallback state for an OAuth client is to do OAuth again.

## Back-channel communication

Many parts of the OAuth process use a normal HTTP request and response format to communicate to each other. Since these requests generally occur outside the purview of the resource owner and user agent, they are collectively referred to as back-channel communication

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/OAuthDance/Images/od2.PNG" />

## Front-channel communication

Front-channel communication is a method of using HTTP requests to communicate indirectly between two systems through an intermediary web browser.

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/OAuthDance/Images/od3.PNG" />

What if my client isn’t a web application?

OAuth can be used by both web applications and native applications, but both need to use the same front-channel mechanism to receive information back from the authorization endpoint. The front channel always uses a web browser and HTTP redirects, but they don’t always have to be served by a regular web server in the end. Fortunately, there are a few useful tricks, such as internal web servers, application specific URI schemes, and push notifications from a back-end service that can be used. As long as the browser can invoke a call on that URI, it will work. We’ll explore all of these options in detail in chapter 6.
