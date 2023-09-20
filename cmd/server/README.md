# Credential Server

The Credential Server serves the User Service, which is defined in an [OpenAPI 3.0 spec](https://spec.openapis.org/oas/v3.0.0) and lives in [`/openapi/user.yaml`](/openapi/user.yaml).

## Usage

### First-time setup

Make sure you have [Bazel](https://bazel.build/) installed. For more detailed instructions on some of the tools we use and how we use them, check out the [Silicon Ally Developer Handbook](https://siliconally.getoutline.com/s/d984f195-3e5e-410f-bce8-63676496661f).

Once that's done, you'll either need access to the sops-encrypted `cmd/server/configs/secrets/local.enc.json` file or otherwise replace it with your own, which should contain the contents:

```json
{
	"auth_private_key": {
		"id": "some-id",
		"data": "-----BEGIN PRIVATE KEY-----\n[ ... the private key ...]\n-----END PRIVATE KEY-----"
	},
	"azure_ad": {
		"tenant_name": "...",
		"user_flow": "B2C_1_...",
		"client_id": "11111111-2222-3333-4444-555555555555",
		"tenant_id": "00000000-9999-8888-7777-666666666666"
	}
}
```

The `azure_ad` section is only required if `use_local_jwts` is false. The `auth_private_key.data` field is the Ed25519 private key used for JWT signing (and the public key is used for validation in the `testcreds` endpoint). To generate a key you can run:

```bash
bazel run //scripts:run_keygen
```

Which will create `test_server.{pub,key}` files in the root of the project. From there, it can be copied into the sops file by running `sops cmd/server/configs/secrets/local.enc.json`.

If you don't do this, you'll get an error like:

```
failed to decrypt secrets: failed to decrypt file: Failed to read "cmd/server/configs/secrets/local.enc.json": open cmd/server/configs/secrets/local.enc.json: no such file or directory
```

or

```
failed to decrypt secrets: failed to decrypt file: Error getting data key: 0 successful groups required, got 0
```

when you try to run the server.

### Running the Credential Server

To run the Credential Server, run:

```bash
# Run the backend 
bazel run //scripts:run_server

# Note: If you want to use Azure instead of local JWTs, run
# bazel run //scripts:run_server -- --use_azure_auth
```

Once all dependencies are installed and the server actually starts, you'll see something that looks like:

```
         █▀▄░█▄█░▀█▀
         █▀▄░█░█░░█░
         ▀░▀░▀░▀░▀▀▀
░█▀▀░█▀▄░█▀▀░█▀▄░█▀▀░█▀▄░█░█
░█░░░█▀▄░█▀▀░█░█░▀▀█░█▀▄░▀▄▀
░▀▀▀░▀░▀░▀▀▀░▀▀░░▀▀▀░▀░▀░░▀░
```

At this point, the server is running and accessible at `localhost:8080`.

### Calling the service

The User API exists to exchange end-user credentials from an auth service (in this case, Azure AD B2C) for RMI-specific credentials. When testing locally, there are two different ways to test things out:

1. **Using the web frontend** - This repo contains a basic web frontend in [the `frontend/` directory](/frontend/), check out [the `README.md` there](/frontend/README.md) for set up and running instructions. The frontend integrates with [Microsoft's MSAL.js](https://github.com/AzureAD/microsoft-authentication-library-for-js) to do the full authentication flow + credential exchange.
  * Make sure to run the server with the `--use_azure_auth` flag.
2. **Using `genjwt`** - The [`genjwt` tool](/cmd/tools/genjwt) uses your local keypair to generate JWTs. It can generate both the `source` JWTs (which would normally be issued by Azure AD et al) and `apikey` JWTs, which are usually the result of the credential exchange

```bash
bazel run //scripts:run_genjwt

# This will output something like:
# Token: <header>.<payload>.<sig>
```

You can take that token from above and exchange it for API credentials, like:

```bash
# Be wary of storing sensitive credentials in your Bash (or similar) history.
APIKEY='<token from above>'
curl -H "Authorization: BEARER $APIKEY" -X POST localhost:8080/login/apikey

# This will output something like:
# {"id":"key123","key":"<another token>"}
```

You can use this new token to query an RMI API:

```bash
APIKEY='<the new token>'
# Check the credentials with the Test API
curl -H "Authorization: BEARER $APIKEY" -X POST localhost:8080/credentials:check
```

## Building and running the Docker container locally

To build and run the image locally:

```bash
# Build the image
bazel build --@io_bazel_rules_go//go/config:pure //cmd/server:image_tarball

# Load it into Docker. This will print out something like:
# Loaded image ID: sha256:<image SHA>
docker load < bazel-bin/cmd/server/image_tarball/tarball.tar

docker run --rm -it sha256:<image SHA from previous step> --config=/configs/local.conf
```

If you get an error like:

```
/server: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by /server)
/server: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by /server)
```

Make sure you included the `--@io_bazel_rules_go//go/config:pure` flag in `bazel build`, see [`pure` docs](https://github.com/bazelbuild/rules_go/blob/master/go/modes.rst#pure). The problem is that without it, the compiled binary dynamically links glibc against your system, which may use a different version of glibc than the Docker container, which currently uses Debian 11 + glibc 2.28
