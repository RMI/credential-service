# RMI Credential Test Frontend

Currently, this is just a barebones frontend used for exchanging Azure AD B2C credentials for RMI-specific JWTs. It is based on [Microsoft's MSAL TypeScript sample app](https://github.com/AzureAD/microsoft-authentication-library-for-js/tree/b29498c2bde71b17035a7e278c5e578917cfd8d3/samples/msal-browser-samples/TypescriptTestApp2.0), and removes everything except the basic authentication flow. It uses [`openapi-typescript-codegen`](https://github.com/ferdikoomen/openapi-typescript-codegen) to generate TypeScript bindings for [the OpenAPI spec](/openapi/user.yaml).

## Usage

### First-time setup

First, install frontend dependencies with:

```bash
cd frontend
npm install
```

Then, create an `auth.json` file in the frontend directory and fill in your Azure AD B2C configuration. An `auth.json.sample` file is provided as an example. If you don't do this step, you'll get an error like:

```
✘ [ERROR] Could not resolve "../auth.json"

    src/AuthModule.ts:12:22:
      12 │ import b2cPolicy from '../auth.json'
         ╵                       ~~~~~~~~~~~~~~

1 error
```

when you try to run the frontend dev server.

Make sure the server is using the same configuration (provided in `cmd/server/configs/local.conf`), it requires the same Azure AD B2C config parameters, in addition to the tenant ID. Check out [the `cmd/server` README](/cmd/server/README.md) for more details. 

# Running the frontend

This frontend uses [ESBuild](https://esbuild.github.io/) to turn the `main.ts` into the compiled JavaScript output and to run the local dev server, which will automatically recompile outputs as they change. To test out the web frontend:

```bash
# From the root directory, run the backend in one terminal.
bazel run //scripts:run_server

# In another terminal, run the frontend
cd frontend
npm run dev
```

From there, you can access the frontend at `localhost:3000`. Click `Sign In` to sign in or create an account against your Azure AD tenant, then click 'Get API Key' to exchange your ID token for an RMI API key.

This API key can then be used with any service that accepts JWTs signed with RMI credentials.
