# goscep

goscep is a small private certificate authority service written in Go. Clients submit a
PKCS#10 certificate signing request (CSR) and goscep signs it with a local CA, after checking
that every requested name falls under a configured list of authorized domains.

The repository builds two programs:

| Program | Image | Purpose |
|---|---|---|
| **goscep** | `shanmugara/goscep-server` | The signing service. Holds the CA key. Serves two HTTPS listeners: SPIFFE mTLS for workloads (9443) and client-certificate TLS for allowlisted clients (8443). |
| **goscep-webui** | `shanmugara/goscep-webui` | A browser front end. Users sign in with a password, paste or upload a CSR, and download the certificate. It submits CSRs to goscep's 8443 port using its own client certificate and never sees the CA key. |

> Despite the name, goscep does not implement the SCEP protocol (RFC 8894). It exposes a
> simple HTTPS API described below.

## Contents

- [Architecture](#architecture)
- [goscep](#goscep-1)
  - [Listeners and authentication](#listeners-and-authentication)
  - [API](#api)
  - [What goes into an issued certificate](#what-goes-into-an-issued-certificate)
  - [Command-line flags](#goscep-command-line-flags)
  - [Configuration files](#goscep-configuration-files)
  - [Container](#goscep-container)
- [goscep-webui](#goscep-webui)
  - [Features](#features)
  - [Command-line flags](#goscep-webui-command-line-flags)
  - [users.yaml](#usersyaml)
  - [Container](#goscep-webui-container)
- [Setting up certificates](#setting-up-certificates)
- [Running both with Docker Compose](#running-both-with-docker-compose)
- [Kubernetes notes](#kubernetes-notes)
- [Building](#building)
- [Testing](#testing)
- [Logging](#logging)
- [Security notes and known limitations](#security-notes-and-known-limitations)

## Architecture

```
                        ┌──────────────────────────────────────────────┐
 SPIFFE workloads ──────▶ :9443  SPIFFE mTLS   JSON {"csrb64": ...}     │
 (SPIRE SVID)           │                                              │
                        │                goscep                        │──▶ signs with ca.crt / ca.key
 Allowlisted clients ───▶ :8443  client cert   raw PEM CSR body         │
 (cert CN in            │        CN allowlist                          │
  allowedcns.yaml)      └──────────────────────▲───────────────────────┘
                                               │ mTLS, CN=goscep-webui...
 Browser ──HTTPS :443 (password login)──▶ goscep-webui
                                          per-user domain limits
```

## goscep

### Listeners and authentication

| Port (default) | Flag | Who connects | How the client is authenticated | Request body |
|---|---|---|---|---|
| **9443** | `-port` | Workloads with a SPIFFE identity | SPIFFE mTLS. goscep fetches its own SVID from the SPIRE agent's Workload API socket and requires the client to present an X.509 SVID from the same trust domain (see [known limitations](#security-notes-and-known-limitations)). | JSON |
| **8443** | `-port-tls` | Allowlisted clients, including goscep-webui | Standard TLS with a **required** client certificate. The certificate must chain to `-ca-root`, carry the `clientAuth` extended key usage, and its subject CN must be listed in `allowedcns.yaml`. Clients that fail any check are rejected during the TLS handshake. | Raw PEM CSR |

Both listeners serve the same endpoint, `POST /v1/cert/request`, and apply the same CSR checks.

goscep exits at startup if it cannot reach the SPIRE agent, because the 9443 listener is set up
first. A SPIRE agent socket is therefore required even if you only use 8443.

### API

#### 9443: JSON request

```http
POST /v1/cert/request
Content-Type: application/json

{"csrb64": "<base64 of the PEM-encoded CSR>"}
```

```bash
printf '{"csrb64":"%s"}' "$(base64 -i host.csr | tr -d '\n')" > req.json
# called from a workload holding an X.509 SVID, e.g. with spiffe-helper-provided certs
curl --cert svid.pem --key svid_key.pem --cacert bundle.pem \
  -H 'Content-Type: application/json' -d @req.json \
  https://goscep.example:9443/v1/cert/request
```

The old `csrpem` field (a file path on the server) is no longer accepted and returns an error.

#### 8443: raw CSR request

```http
POST /v1/cert/request
Content-Type: application/pkcs10

-----BEGIN CERTIFICATE REQUEST-----
...
-----END CERTIFICATE REQUEST-----
```

```bash
curl --cert client.crt --key client.key --cacert ca.crt \
  -H 'Content-Type: application/pkcs10' \
  --data-binary @host.csr \
  https://goscep.example:8443/v1/cert/request | jq -r .certificate > host.crt
```

Use `--data-binary`, not `-d`: `-d` strips newlines and breaks the PEM. The body is limited to
64 KiB and must be PEM with the `CERTIFICATE REQUEST` header.

#### Responses (both ports)

| Status | Body | Meaning |
|---|---|---|
| 200 | `{"certificate": "-----BEGIN CERTIFICATE-----\n..."}` | Issued certificate, PEM |
| 400 | `{"error": "..."}` | Bad or unparseable CSR, a name outside `-authorized-domains`, a CA certificate requested, or an empty or oversized body |
| 500 | `{"error": "..."}` | Signing failed, e.g. the CA files could not be read |

### What goes into an issued certificate

| Field | Value |
|---|---|
| Subject | Copied from the CSR |
| DNS SANs | Copied from the CSR. If the CSR has none, the CN is added as a DNS SAN. |
| IP SANs | Copied from the CSR (not checked against any list) |
| Key usage / extended key usage | Copied from the CSR's `keyUsage` and `extendedKeyUsage` extensions |
| Basic constraints | Always `CA:FALSE`. CSRs that ask for `CA:TRUE` are rejected. |
| Validity | From now to now + `-validity-years` |
| Serial number | 128-bit random |
| Signature | By the key in `-ca-key` |

**Name checks:** the CN and every DNS SAN must end with one of the `-authorized-domains`
values. The check is a plain suffix match, so include the leading dot (`.omegaworld.net`) if
you need to prevent names like `evilomegaworld.net` from matching.

### goscep command-line flags

| Flag | Default | Description |
|---|---|---|
| `-ca-root` | `ca.crt` | CA certificate (PEM). Used to sign, and as the trust anchor for 8443 client certificates. |
| `-ca-key` | `ca.key` | CA private key. **Must be unencrypted PKCS#8** (`-----BEGIN PRIVATE KEY-----`). |
| `-tls-cert` | `tls.crt` | Server certificate for the 8443 listener |
| `-tls-key` | `tls.key` | Key for `-tls-cert` |
| `-port` | `9443` | SPIFFE mTLS listener port |
| `-port-tls` | `8443` | Client-certificate TLS listener port |
| `-server` | `0.0.0.0` | Listen address for both listeners |
| `-authorized-domains` | *(none)* | Comma-separated domain suffixes goscep may issue for. Can be repeated. **With no value, every request is refused.** |
| `-allowed-cns` | `allowedcns.yaml` | Client-certificate CN allowlist for 8443 |
| `-validity-years` | `1` | Lifetime of issued certificates |
| `-spiffe-ids` | `spiffeids.yaml` | Intended allowlist of SPIFFE IDs for 9443. **Currently not used**; see [known limitations](#security-notes-and-known-limitations). |

Relative paths are resolved against the working directory, which is `/app` in the container.
Passing absolute paths to a mounted directory, as in the examples below, is clearer.

### goscep configuration files

#### `allowedcns.yaml`

```yaml
allowedcns:
  - goscep-webui.omegaworld.net
  - omegareq-client.omegaworld.net
```

- The key is `allowedcns`, all lowercase. A different key such as `allowedCNs` parses without
  error but yields an empty list.
- The file is read once at startup. Restart goscep after editing it.
- If the file is missing or unreadable, goscep logs a warning and **8443 rejects every client**.

#### CA key format

goscep only reads PKCS#8 keys. Convert an RSA (`BEGIN RSA PRIVATE KEY`) or EC key with:

```bash
openssl pkcs8 -topk8 -nocrypt -in ca-traditional.key -out ca.key
```

### goscep container

**Image:** `shanmugara/goscep-server:<tag>`
**Entrypoint:** `/app/goscep`; arguments after the image name are passed as flags.

| Exposed port | Purpose |
|---|---|
| `9443` | SPIFFE mTLS listener |
| `8443` | Client-certificate TLS listener |

**Environment:**

| Variable | Default in image | Purpose |
|---|---|---|
| `SPIFFE_ENDPOINT_SOCKET` | `unix:///tmp/spire-agent/public/api.sock` | SPIRE agent Workload API socket |

**Volumes to mount:**

| Container path | Contents | Mode |
|---|---|---|
| `/tmp/spire-agent/public/` | The SPIRE agent socket directory from the host (declared as a `VOLUME` in the image) | read-write |
| `/etc/goscep/` (your choice) | `ca.crt`, `ca.key`, `tls.crt`, `tls.key`, `allowedcns.yaml` | read-only |

**Example:**

```bash
docker run -d --name goscep \
  -p 9443:9443 -p 8443:8443 \
  -v /run/spire/agent/public:/tmp/spire-agent/public \
  -v /srv/goscep:/etc/goscep:ro \
  shanmugara/goscep-server:<tag> \
    -ca-root /etc/goscep/ca.crt \
    -ca-key /etc/goscep/ca.key \
    -tls-cert /etc/goscep/tls.crt \
    -tls-key /etc/goscep/tls.key \
    -allowed-cns /etc/goscep/allowedcns.yaml \
    -authorized-domains omegaworld.net \
    -validity-years 1
```

Replace `/run/spire/agent/public` with wherever the SPIRE agent on the host puts its socket.
The SPIRE agent must have a registration entry that matches the goscep container, or goscep
cannot fetch its SVID and exits.

Expected startup log:

```
level=info msg="Authorized Domains: [omegaworld.net]"
level=info msg="using SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock"
level=info msg="Starting tls server 0.0.0.0 on port 8443"
level=info msg="Starting mtls server 0.0.0.0 on port 9443"
```

A line `failed to load allowed CNs` means 8443 will reject everyone; check the mount and the
`-allowed-cns` path.

## goscep-webui

### Features

- **Sign-in:** username and password from `users.yaml` (bcrypt hashes).
- **CSR input:** paste PEM text, or upload a `.csr`/`.pem`/`.der` file. Both PEM headers
  (`CERTIFICATE REQUEST` and `NEW CERTIFICATE REQUEST`) and raw DER are accepted.
- **Per-user domain limits:** each user may only request names inside their
  `allowed_domains`. This is checked before anything is sent to goscep. goscep's own
  `-authorized-domains` check still applies on top.
- **Download:** the result page shows the certificate's subject, names, serial and expiry, a
  **Download** button (`<cn>.crt`), and the PEM text for copying.
- **Issuance through goscep 8443:** the web UI calls goscep with its own client certificate
  and sends the user name in an informational `X-Goscep-User` header.

**Request checks performed by the web UI:**

| Check | Result if it fails |
|---|---|
| CSR parses and its signature verifies | 400 |
| CSR contains only DNS names (no IP, URI or email SANs) | 403 |
| The CN and every DNS SAN equal or sit under one of the user's `allowed_domains`. Matching respects label boundaries: `omegaworld.net` allows `host.omegaworld.net` but not `evilomegaworld.net`. | 403 |
| goscep accepts the request | goscep's 4xx error message is shown to the user |
| goscep is reachable and returns a certificate | 502 with a generic message; details go to the log |

**Session and login protection:**

| Control | Behavior |
|---|---|
| Session cookie | `goscep_session`, HMAC-SHA256 signed, `HttpOnly`, `Secure`, `SameSite=Strict`, no server-side storage |
| Idle timeout | `-session-ttl` (30 minutes); the cookie is refreshed while the user is active |
| CSRF | Every POST form carries a per-user token |
| Lockout | 5 failed sign-ins for the same IP and username lock that pair out for 15 minutes |
| User removal | Removing a user from `users.yaml` ends their session on their next request |
| Headers | `Content-Security-Policy`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` |

**Routes:**

| Route | Purpose |
|---|---|
| `GET /login`, `POST /login` | Sign-in page and form |
| `GET /` | CSR submission page (requires sign-in) |
| `POST /submit` | Submit a CSR (requires sign-in and CSRF token) |
| `POST /logout` | Sign out |
| `GET /static/...` | Stylesheet |

### goscep-webui command-line flags

| Flag | Default | Description |
|---|---|---|
| `-listen` | `:443` | HTTPS listen address |
| `-users` | `/scep/users.yaml` | Users file |
| `-tls-cert` | `/scep/webui-tls.crt` | HTTPS certificate shown to browsers. Its SAN must match the hostname users open. |
| `-tls-key` | `/scep/webui-tls.key` | Key for `-tls-cert` |
| `-client-cert` | `/scep/webui-client.crt` | Client certificate presented to goscep on 8443. Needs `clientAuth`, and its CN must be in goscep's `allowedcns.yaml`. |
| `-client-key` | `/scep/webui-client.key` | Key for `-client-cert` |
| `-ca` | `/scep/ca.crt` | CA used to verify goscep's 8443 server certificate |
| `-goscep-url` | `https://goscep:8443/v1/cert/request` | goscep 8443 endpoint. The hostname must match a SAN in goscep's `tls.crt`. |
| `-session-ttl` | `30m` | Session idle timeout (Go duration, e.g. `15m`, `1h`) |
| `-session-key-file` | *(empty)* | File with at least 32 bytes used to sign session cookies. If empty, a random key is generated at each start: sessions end on restart and are not shared between replicas. |
| `-hash-password` | `false` | Read a password from stdin, print its bcrypt hash and exit |

### users.yaml

```yaml
users:
  - username: alice
    password_hash: "$2a$10$Qm3...."
    allowed_domains:
      - omegaworld.net          # alice may request omegaworld.net and any *.omegaworld.net name
  - username: bob
    password_hash: "$2a$10$9xK...."
    allowed_domains:
      - web.omegaworld.net      # bob may only request web.omegaworld.net and its subdomains
```

| Field | Required | Notes |
|---|---|---|
| `username` | yes | Must be unique |
| `password_hash` | yes | A bcrypt hash; plain-text passwords are rejected at load time |
| `allowed_domains` | yes, at least one | Domain names without wildcards. Each entry allows the domain itself and any subdomain. |

**Creating a password hash:**

```bash
docker run --rm -i shanmugara/goscep-webui:<tag> -hash-password
Password: <type the password, then Enter>
$2a$10$....
```

The password is echoed while typing. To avoid that, pipe it in:
`printf '%s\n' "$PASSWORD" | docker run --rm -i shanmugara/goscep-webui:<tag> -hash-password`.
Passwords must be at least 8 characters.

**Reloading:** the file is checked on every request and reloaded when its modification time
changes, so edits (including Kubernetes ConfigMap updates) take effect without a restart. An
invalid edit is logged and the last good version stays in use. At startup, an invalid or empty
file stops the program.

### goscep-webui container

**Image:** `shanmugara/goscep-webui:<tag>`
**Entrypoint:** `/app/goscep-webui`; arguments after the image name are passed as flags.

| Exposed port | Purpose |
|---|---|
| `443` | Web UI over HTTPS |

**Volume to mount: `/scep`** (declared as a `VOLUME` in the image). With the default flags it
must contain:

| File | Purpose | Required |
|---|---|---|
| `users.yaml` | Users, password hashes and allowed domains | yes |
| `webui-tls.crt`, `webui-tls.key` | HTTPS certificate and key for browsers | yes |
| `webui-client.crt`, `webui-client.key` | Client certificate and key for calling goscep 8443 | yes |
| `ca.crt` | CA that signed goscep's 8443 server certificate | yes |
| `session.key` | Session signing key (pass `-session-key-file /scep/session.key`) | recommended |

Create the session key once and keep it stable:

```bash
openssl rand -hex 32 > session.key
```

**Example:**

```bash
docker run -d --name goscep-webui \
  -p 443:443 \
  -v /srv/goscep-webui:/scep:ro \
  shanmugara/goscep-webui:<tag> \
    -goscep-url https://goscep.omegaworld.net:8443/v1/cert/request \
    -session-key-file /scep/session.key
```

The container runs as root so it can bind port 443. To run without root, listen on a high port
and map it, e.g. `-p 443:8444 ... -listen :8444`.

Expected startup log:

```
level=info msg="Loaded 2 web UI users from /scep/users.yaml"
level=info msg="Starting web UI on :443, submitting CSRs to https://goscep.omegaworld.net:8443/v1/cert/request"
```

## Setting up certificates

Everything below is signed by the same CA that goscep uses (`ca.crt` / `ca.key`). On macOS the
system `openssl` is LibreSSL, which does not copy extensions from a CSR when signing, so the
examples pass the extensions explicitly with `-extfile ... -extensions`.

### 1. goscep 8443 server certificate (`tls.crt`)

`goscep-tls.conf`:

```ini
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[dn]
O  = Omegaworld
CN = goscep.omegaworld.net

[req_ext]
subjectAltName   = DNS:goscep.omegaworld.net, DNS:goscep
basicConstraints = critical, CA:FALSE
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
```

```bash
openssl req -new -newkey rsa:2048 -nodes -config goscep-tls.conf -keyout tls.key -out tls.csr
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -sha256 \
  -extfile goscep-tls.conf -extensions req_ext -out tls.crt
```

Include every hostname clients use to reach 8443, including the one in goscep-webui's
`-goscep-url`.

### 2. goscep-webui client certificate (`webui-client.crt`)

`webui-client.conf`:

```ini
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[dn]
O  = Omegaworld
CN = goscep-webui.omegaworld.net

[req_ext]
subjectAltName   = DNS:goscep-webui.omegaworld.net
basicConstraints = critical, CA:FALSE
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
```

```bash
openssl req -new -newkey rsa:2048 -nodes -config webui-client.conf \
  -keyout webui-client.key -out webui-client.csr
openssl x509 -req -in webui-client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -sha256 \
  -extfile webui-client.conf -extensions req_ext -out webui-client.crt
```

Then add `goscep-webui.omegaworld.net` to goscep's `allowedcns.yaml` and restart goscep.

### 3. goscep-webui HTTPS certificate (`webui-tls.crt`)

The same as step 2, but with `extendedKeyUsage = serverAuth` and a SAN for the hostname users
type in their browser. Browsers must trust the issuing CA, so either distribute `ca.crt` to
users' trust stores or use a certificate from a CA they already trust.

You can use one certificate for both roles (`extendedKeyUsage = serverAuth, clientAuth`) if
users open the web UI at the same hostname as its client CN. Separate key pairs are better:
a leak of the internet-facing HTTPS key then does not also give away the identity goscep trusts.

### 4. Other 8443 clients

Any other client of 8443 needs a certificate like step 2 with its own CN, added to
`allowedcns.yaml`. See [API](#8443-raw-csr-request) for the request format.

### Checking a certificate

```bash
openssl x509 -in webui-client.crt -noout -text | grep -A1 -E "Subject:|Key Usage|Alternative"
```

## Running both with Docker Compose

```yaml
services:
  goscep:
    image: shanmugara/goscep-server:<tag>
    command:
      - -ca-root=/etc/goscep/ca.crt
      - -ca-key=/etc/goscep/ca.key
      - -tls-cert=/etc/goscep/tls.crt
      - -tls-key=/etc/goscep/tls.key
      - -allowed-cns=/etc/goscep/allowedcns.yaml
      - -authorized-domains=omegaworld.net
    ports:
      - "9443:9443"
      - "8443:8443"
    volumes:
      - /run/spire/agent/public:/tmp/spire-agent/public
      - ./goscep:/etc/goscep:ro
    restart: unless-stopped

  goscep-webui:
    image: shanmugara/goscep-webui:<tag>
    command:
      - -goscep-url=https://goscep:8443/v1/cert/request
      - -session-key-file=/scep/session.key
    ports:
      - "443:443"
    volumes:
      - ./goscep-webui:/scep:ro
    depends_on:
      - goscep
    restart: unless-stopped
```

Here the web UI reaches goscep at `https://goscep:8443`, so goscep's `tls.crt` must include
`DNS:goscep` as a SAN (as in [step 1](#1-goscep-8443-server-certificate-tlscrt)).

Directory layout:

```
./goscep/        ca.crt  ca.key  tls.crt  tls.key  allowedcns.yaml
./goscep-webui/  ca.crt  users.yaml  webui-tls.crt  webui-tls.key
                 webui-client.crt  webui-client.key  session.key
```

Only `ca.crt` is shared between the two. `ca.key` belongs to goscep alone.

## Kubernetes notes

| What | goscep | goscep-webui |
|---|---|---|
| Secrets | `ca.key`, `tls.key` (and certs) mounted read-only, e.g. at `/etc/goscep` | `webui-tls.key`, `webui-client.key`, `session.key` mounted at `/scep` |
| ConfigMaps | `allowedcns.yaml` (restart the pod after changing it) | `users.yaml` (picked up automatically) |
| SPIRE | Mount the agent socket with the SPIFFE CSI driver or a `hostPath` at `/tmp/spire-agent/public`, and create a registration entry for the pod | not needed |
| Service | ports 9443 and 8443 | `port: 443` → `targetPort: 443` (or a high port if you run non-root) |
| Replicas | Any number. Each pod reads the same CA files. | More than one needs a shared `session.key`. Login lockout counters are per pod. |

When `users.yaml` and the secrets need to live in the same `/scep` directory, use a
`projected` volume to combine the ConfigMap and Secret.

## Building

```bash
# binaries
go build -o goscep .
go build -o goscep-webui ./cmd/webui

# images
docker build --platform linux/amd64 -f Dockerfile       -t shanmugara/goscep-server:<tag> .
docker build --platform linux/amd64 -f Dockerfile.webui -t shanmugara/goscep-webui:<tag> .
```

`Dockerfile.webui` cross-compiles on the build machine's own architecture, so building amd64
images on Apple Silicon works without emulation. `Dockerfile` (goscep) still compiles inside an
amd64 container; on Apple Silicon that runs under emulation and the Go toolchain can crash with
`SIGSEGV`. Either enable Rosetta in Docker Desktop or apply the same
`--platform=$BUILDPLATFORM` / `GOOS`/`GOARCH` pattern used in `Dockerfile.webui`.

The Jenkinsfile builds and pushes only `goscep-server` from `main`.

## Testing

```bash
go test ./...
```

`webui/webui_test.go` contains an end-to-end test that runs goscep's real 8443 handler and TLS
configuration (including the CN allowlist) with a throwaway CA, then drives the web UI through
sign-in, CSR submission, download, per-user domain limits, CSRF, lockout and logout.

### Manual test of 8443

```bash
curl --cert client.crt --key client.key --cacert ca.crt \
  -H 'Content-Type: application/pkcs10' --data-binary @host.csr \
  https://goscep.omegaworld.net:8443/v1/cert/request
```

| Test | Expected |
|---|---|
| Without `--cert`/`--key` | TLS error: `certificate required` |
| Client CN not in `allowedcns.yaml` | TLS error: `bad certificate` |
| Client certificate without `clientAuth` | TLS error: `bad certificate` |
| CSR for a name outside `-authorized-domains` | 400 `unauthorized for domain` |
| Body that is not a CSR | 400 `invalid CSR` |

## Logging

Both programs log to stderr in logrus text format.

goscep logs each request's parsing, names and key usages, plus Gin's access log line per
request. goscep-webui writes an audit trail with structured fields:

```
level=info msg="Login succeeded" event=login ip=10.0.0.5 user=alice
level=warning msg="Rejected CSR" event=issue ip=10.0.0.5 names="[host.example.org]" user=alice error="you are not allowed to request host.example.org ..."
level=info msg="Certificate issued" event=issue ip=10.0.0.5 names="[host.omegaworld.net]" serial=8E5C... user=alice
```

goscep only sees the web UI's client identity. To find out which person requested a
certificate, use the web UI's `event=issue` log lines (matched by serial number).

## Security notes and known limitations

- **`ca.key` is the crown jewel.** Mount it read-only into goscep only. The web UI never needs
  it. A copy is committed to this repository's history; treat that key as a test key, not for
  production.
- **`-spiffe-ids` is not used.** goscep never passes the file to the SPIFFE library, which then
  falls back to accepting *any* workload in goscep's trust domain on 9443. Wiring it requires
  setting `AllowedSpiffeIDsFile: Config.SpiffeIDs` where `spireauthlib.ServerAuth` is created in
  `scep/server.go`.
- **9443 can issue names on the 8443 allowlist.** A SPIFFE workload can request a certificate
  whose CN is, for example, `goscep-webui.omegaworld.net` and then use it on 8443 with the same
  rights as the web UI. Until goscep refuses to issue allowlisted CNs through 9443, keep the set
  of workloads allowed on 9443 tight.
- **Domain matching in goscep is a plain suffix check.** Use `.omegaworld.net` (with the dot)
  in `-authorized-domains` if `evilomegaworld.net` must not match. The web UI's own per-user
  check already respects label boundaries.
- **IP SANs are not checked by goscep.** The web UI refuses them; direct 8443 and 9443 clients
  can still request them.
- **`allowedcns.yaml` is read once.** An empty or mistyped file silently locks out every 8443
  client; watch for `failed to load allowed CNs` at startup.
- **No health endpoint.** Use a TCP check on the listener ports.
- **Revocation is not supported.** goscep does not publish a CRL or run OCSP. Keep
  `-validity-years` short.
