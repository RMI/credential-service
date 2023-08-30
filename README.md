# Credential Service

Credential Service is an API that exchanges authentication tokens from auth systems (think Auth0, Azure AD B2C, Firebase Auth, etc) for ecosystem-specific tokens, such that they can be used with any RMI service. The API is defined in an [OpenAPI v3 spec](/openapi/user.yaml), and currently only supports Azure AD B2C ID tokens as input.

The service currently has two main credential-exchanging endpoints:

- CreateAPIKey - Creates a new API key, returns it in the response body.
  - Intended to be used for programmatically accessing RMI APIs
  - `POST /login/apikey`
- CookieLogin - Creates a new API key, returns it in a `Set-Cookie` response
  - Intended to be used for web clients
  - `POST /login/cookie`

Things to note:

- Only Azure AD B2C is supported as a source of exchangable user ID tokens at the moment, see [the server `main.go`](/cmd/server/main.go) and the [`azjwt` package](/azure/azjwt/azjwt.go) for more details.

## Running the Credential Service

Run the server against an Azure AD B2C instance:

```bash
bazel run //scripts:run_server -- --use_azure_auth
```

Run the server against a local JWT issuer, see [the cmd/server README](/cmd/server/README.md) for more details:

```bash
bazel run //scripts:run_server
```

You can access the API via `curl`, see [the cmd/server README](/cmd/server/README.md) for more details and exact commands.

## Security

Please report security issues to security@siliconally.org, or by using one of
the contact methods available on our
[Contact Us page](https://siliconally.org/contact/).

## Contributing

Contribution guidelines can be found [on our website](https://siliconally.org/oss/contributor-guidelines).
