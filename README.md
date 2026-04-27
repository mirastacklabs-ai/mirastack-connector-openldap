# mirastack-connector-openldap

OpenLDAP identity-provider connector for MIRASTACK. Authenticates users against
an OpenLDAP (or any LDAP v3-compatible) directory and integrates with the
Mirastack AAAA framework via the `IdentityProviderService` gRPC contract.

**License**: GNU Affero General Public License v3.0 (AGPL-3.0-only)

---

## How it works

1. The connector registers itself with the Mirastack Engine on startup using the
   standard connector SDK `RegisterPlugin` handshake.
2. Because `Info().Metadata["identity_provider"] == "true"`, the engine
   automatically creates a `GRPCProvider` backed by this connector and adds it
   to the provider registry.
3. When a user submits their credentials via the Mirastack login endpoint, the
   engine calls the connector's `Authenticate` RPC (three-step LDAP bind flow).
4. On success, the engine performs JIT user provisioning: a local `User` record
   is created (or refreshed) so role-based access control, audit logging, and
   session management work exactly as they do for local users.

---

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `MIRASTACK_ENGINE_ADDR` | Yes | — | Engine gRPC address, e.g. `mirastack-engine:9000` |
| `MIRASTACK_GRPC_ADDR` | Yes | — | Address this connector listens on, e.g. `0.0.0.0:9100` |
| `MIRASTACK_PROVIDER_NAME` | No | `openldap` | Name registered with the engine |
| `MIRASTACK_PLUGIN_VERSION` | No | `1.0.0` | Semantic version reported in `Info()` |
| `LDAP_URL` | Yes | `ldap://localhost:389` | LDAP server URL (`ldap://` or `ldaps://`) |
| `LDAP_BIND_DN` | Yes | — | Service-account DN for directory searches |
| `LDAP_BIND_PASSWORD` | Yes | — | Service-account password |
| `LDAP_BASE_DN` | Yes | — | LDAP search base, e.g. `dc=corp,dc=local` |
| `LDAP_USER_FILTER` | No | `(mail=%s)` | LDAP filter template; `%s` is replaced with the user email |
| `LDAP_ATTR_EMAIL` | No | `mail` | Attribute holding the user email |
| `LDAP_ATTR_DISPLAY_NAME` | No | `displayName` | Attribute for the display name |
| `LDAP_ATTR_USERNAME` | No | `sAMAccountName` | Attribute for the local username |
| `LDAP_ATTR_ROLE` | No | *(empty)* | Optional attribute for role mapping (see below) |
| `LDAP_DEFAULT_ROLE` | No | `operator` | Role when `LDAP_ATTR_ROLE` is absent or unmapped |
| `LDAP_TLS_SKIP_VERIFY` | No | `false` | Skip TLS verification (development only) |
| `LDAP_TIMEOUT_SECONDS` | No | `10` | Per-operation LDAP timeout |
| `LOG_LEVEL` | No | `info` | Logging level (`debug`, `info`, `warn`, `error`) |

### Role mapping via `LDAP_ATTR_ROLE`

When `LDAP_ATTR_ROLE` is set, the attribute value is mapped to a Mirastack role:

| LDAP attribute value | Mirastack role |
|---|---|
| `operator` or `mirastack-operator` | `operator` |
| `engineer` or `mirastack-engineer` | `engineer` |
| `admin`, `mirastack-admin`, or `administrator` | `admin` |
| *(any other value)* | value of `LDAP_DEFAULT_ROLE` |

---

## Building

```bash
go build -o mirastack-connector-openldap .
```

## Running (development)

```bash
export MIRASTACK_ENGINE_ADDR=localhost:9000
export MIRASTACK_GRPC_ADDR=0.0.0.0:9100
export LDAP_URL=ldap://localhost:389
export LDAP_BIND_DN="cn=admin,dc=example,dc=com"
export LDAP_BIND_PASSWORD=secret
export LDAP_BASE_DN="dc=example,dc=com"

./mirastack-connector-openldap
```

## Docker Compose snippet

```yaml
services:
  connector-openldap:
    image: ghcr.io/mirastacklabs-ai/mirastack-connector-openldap:latest
    environment:
      MIRASTACK_ENGINE_ADDR: mirastack-engine:9000
      MIRASTACK_GRPC_ADDR: "0.0.0.0:9100"
      LDAP_URL: ldap://openldap:389
      LDAP_BIND_DN: "cn=admin,dc=corp,dc=local"
      LDAP_BIND_PASSWORD: "${LDAP_BIND_PASSWORD}"
      LDAP_BASE_DN: "dc=corp,dc=local"
      LDAP_USER_FILTER: "(mail=%s)"
      LDAP_DEFAULT_ROLE: operator
    ports:
      - "9100:9100"
```
