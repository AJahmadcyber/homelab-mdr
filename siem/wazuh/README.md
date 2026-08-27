# Wazuh single-node stack

Manager, indexer and dashboard. Everything the stack needs is here except the
TLS certificates, which are generated locally in one step and are specific to
the machine that generates them.

## Order matters

```bash
cp .env.example .env          # then change every value in it
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Certificates first. The main compose file bind-mounts ten certificate files
that do not exist until the generator has run, and Docker responds to a missing
bind-mount source by silently creating a root-owned directory in its place — so
the stack starts, the indexer fails TLS, and the cause is two steps back.

`config/certs.yml` drives the generator and lists the three node names the
certificates are issued for. Leave it alone unless the service names in the
compose file change.

## Verify before moving on

```bash
docker compose ps                          # all three services up
docker compose exec wazuh.manager /var/ossec/bin/wazuh-control status
curl -sk -u admin:"$INDEXER_PASSWORD" https://localhost:9200/_cluster/health
```

A container reporting `Up` is not the same as the engine running inside it, so
check `wazuh-control status` rather than trusting `docker compose ps` alone.
Single-node cluster health of `yellow` is expected: replicas cannot be assigned
with one node, and nothing is wrong.

## Credentials

`.env` carries the three passwords. Two of them also exist as bcrypt hashes in
`config/wazuh_indexer/internal_users.yml`, which ships with Wazuh's published
default hashes — changing `.env` alone leaves the indexer still accepting the
defaults. Regenerate the hashes with the tool inside the indexer container and
replace them in that file at the same time.

The `<cluster><key>` value in `config/wazuh_cluster/wazuh_manager.conf` is a
placeholder. A single-node deployment does not use it, but it must be a valid
32-character hex string if a second node is ever added.
