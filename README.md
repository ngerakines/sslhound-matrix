# sslhound-matrix

This is just a proof of concept Matrix bot that can run SSL checks.

# Build

There are only a couple of key dependencies:

* github.com/miekg/dns - For external DNS resolution if configured
* golang.org/x/crypto/ocsp - For OCSP verification

The `github.com/ngerakines/sslhound-matrix/cmd` package contains the main file and entry point.

# Configuration

A configuration file (`config.json`) is required. It must contain the user id, access token, and matrix server to connect to.

```json
{
  "user_id": "@sslhound:your.matrix.host",
  "access_token": "redacted",
  "home_server": "https://your.matrix.host/",
}
```

# Quick Start

1. Create the sslhound user on your matrix server:
   
   register_new_matrix_user -c path/to/homeserver.yaml https://localhost:8008/

2. Login and get credentials:
   
   curl --data '{"identifier": {"type": "m.id.user", "user": "sslhound" }, "password": "yourpassword", "type": "m.login.password", "device_id": "sslhoundbot", "initial_device_display_name": "sslhound"}' https://your.matrix.host/_matrix/client/r0/login

3. Create a configuration file using the information above. Be sure to set the full matrix URL.
4. Run the bot
   
   go run ./cmd/main.go --config ./path/to/config

5. Invite the bot to a channel:
   
   /invite @sslhound:your.matrix.host
6. Request a check:
   
   !check your.matrix.host:443