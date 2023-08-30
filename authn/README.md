# Authentication

The credential service + frontend support a basic authentication flow using Microsoft Azure Active Directory B2C, which looks roughly like the following:

1. User signs up and signs in w/Azure, using [MSAL.js v2](https://github.com/AzureAD/microsoft-authentication-library-for-js)
2. The browser receives an [Azure ID token](https://learn.microsoft.com/en-us/azure/active-directory-b2c/tokens-overview#token-types)
3. The browser exchanges that with the User service at the `/login/cookie` endpoint
    * The ID token should be sent in the `Authorization` header as `Bearer <jwt>`
    * Or, in the case of an API key (e.g. token returned in response, instead of via `Set-Cookie` header) at `/login/apikey`
4. The browser receives a `jwt` cookie
    * The cookie is the same format as an API key, both for simplicity and so that the same auth can be used in the browser and for API clients (e.g. `curl`, other apps)
5. The browser can use that cookie to access RMI APIs, like OPGEE + PACTA.