# What is OAuth 2 and why should you care?

## What is OAuth 2.0?

OAuth 2.0 is a **delegation protocol**, a means of letting someone who controls a resource allow a software application to access that resource on their behalf without impersonating them.

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/FirstSteps/Images/fs1.PNG" />

* The **resource owner** has access to an API and can delegate access to that API. The resource owner is usually a person and is generally assumed to have access to a web browser.

* The **protected resource** is the component that the resource owner has access to.

* The **client** is the piece of software that accesses the protected resource on behalf of the resource owner.

## The bad old days: credential sharing (and credential theft)

the client is **impersonating** the user, and the protected resource has no way to tell the difference between the resource owner and the impersonating client because they’re using the same username and password in the same way.

Why is that undesirable? Consider that you don’t want the printing service to be able to upload or delete photos from the storage service. Resource owner want to delegate part of his authority to the client.

## Delegating access

in OAuth, the end user delegates some part of their authority to access the protected resource to the client application to act on their behalf. To make that happen, OAuth introduces another component into the system: the **authorization server**.

To acquire a token, the client first sends the resource owner to the authorization server in order to request that the resource owner authorize this client. 

The resource owner authenticates to the authorization server and is generally presented with a choice of whether to authorize the client making the request. 

The client is able to ask for a subset of functionality, or scopes, which the resource owner may be able to further diminish. 

Once the authorization grant has been made, the client can then request an access token from the authorization server. This access token can be used at the protected resource to access the API, as granted by the resource owner

- - -> means **redirect**

<img src="https://github.com/KiraDiShira/OAuth2/blob/master/FirstSteps/Images/fs2.PNG" />

## What OAuth 2.0 isn’t

OAuth isn’t defined outside of the HTTP protocol. Since OAuth 2.0 with bearer tokens provides no message signatures, it is not meant to be used outside of HTTPS (HTTP over TLS). Sensitive secrets and information are passed over the wire, and OAuth requires a transport layer mechanism such as TLS to protect these secrets.

