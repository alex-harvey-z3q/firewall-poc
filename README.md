# Hiera-driven host firewalls for two Azure applications

This proof of concept puts **groups, services, application contracts and allowed relationships in checked-in Hiera YAML**. Puppet looks up that data and resolves it into `firewall_multi` resources during catalogue compilation. `puppetlabs/firewall` installs the individual Linux rules. There is no external rule-generation step.

Terraform provisions six private Linux VMs: web, API and database tiers for each of two hypothetical applications. Every VM defaults to DROP for INPUT, OUTPUT and FORWARD. There is no Azure Firewall or NSG enforcement layer.

Start with these files:

| Hiera file | What you configure |
|---|---|
| [`puppet/data/groups.yaml`](puppet/data/groups.yaml) | Node groups, nested groups, network groups and external IPAM references |
| [`puppet/data/policy.yaml`](puppet/data/policy.yaml) | Named services, application roles, contracts and allowed connections |
| [`puppet/data/inventory.yaml`](puppet/data/inventory.yaml) | VM addresses and tier subnets; also read directly by Terraform |
| [`puppet/data/common.yaml`](puppet/data/common.yaml) | Replacement lookup semantics, so merges cannot retain revoked grants |
| [`puppet/data/external/ipam.example.json`](puppet/data/external/ipam.example.json) | Example IPAM Hiera document; the live `ipam.json` is ignored by Git |
| [`puppet/hiera.yaml`](puppet/hiera.yaml) | The Hiera hierarchy |

## Architecture

App A is Ordering — a hypothetical order-processing application; App B is Inventory. Ordering's API calls Inventory's API.

```text
                      application_users (IPAM)
                                |
                +---------------+---------------+
                |                               |
             TCP 8080                        TCP 8080
                v                               v
  Azure VNet 10.42.0.0/16 - private addresses only
  +-------------------------------------------------------------------+
  |                                                                   |
  |    APP A: ORDERING                 APP B: INVENTORY               |
  |                                                                   |
  |    +------------------+            +------------------+           |
  |    | Web              |            | Web              |           |
  |    | 10.42.1.10       |            | 10.42.1.20       |           |
  |    +--------+---------+            +--------+---------+           |
  |             | TCP 9000                      | TCP 9000            |
  |             v                               v                     |
  |    +------------------+            +------------------+           |
  |    | API              |--TCP 9000->| API              |           |
  |    | 10.42.2.10       |            | 10.42.2.20       |           |
  |    +--------+---------+            +--------+---------+           |
  |             | TCP 15432                     | TCP 15432           |
  |             v                               v                     |
  |    +------------------+            +------------------+           |
  |    | Database         |            | Database         |           |
  |    | 10.42.3.10       |            | 10.42.3.20       |           |
  |    +------------------+            +------------------+           |
  |                                                                   |
  +-------------------------------------------------------------------+

  Each box is a Linux VM with a local firewall.
  Arrows show permitted connection initiation; matching replies are allowed.
  Administrators (IPAM): SSH/TCP 22 to all six VMs.
  Each VM: only the required Azure platform traffic and host baseline.
  All other network traffic: DROP, including forwarding.

  CONFIGURATION

  Hiera YAML ------+
                   +--> Puppet --> firewall_multi --> local firewall rules
  IPAM --> import -+
```

Subnets organise addresses; they do not grant trust. Each internal connection requires both a source OUTPUT rule and a destination INPUT rule. The example services are synthetic HTTP listeners, **including the database tier**. They illustrate connectivity, not a production application, TLS configuration or database engine.

## Configure logical groups in Hiera

`groups.yaml` contains ordinary operator-authored data:

```yaml
profile::policy::groups:
  app_a.web:
    nodes: [app_a-web]
  app_a.api:
    nodes: [app_a-api]
  app_a.db:
    nodes: [app_a-db]
  app_a:
    members: [app_a.web, app_a.api, app_a.db]
  application_hosts:
    members: [app_a, app_b]
  azure_platform:
    networks: [168.63.129.16/32]
  administrators:
    ipam: external.admins
  application_users:
    ipam: external.clients
```

The complete file also defines App B. A group has exactly one of four kinds:

- `nodes`: inventory node names, resolved to their `/32` addresses.
- `members`: other logical group names; nesting is supported and cycles rejected.
- `networks`: explicit, reviewed IPv4 CIDRs.
- `ipam`: a reference to an externally supplied group.

VM IPs are not repeated in the policy. The inventory is the shared address authority for both Puppet and Terraform. Unknown nodes/groups, cycles and ambiguous group definitions fail catalogue compilation. Empty groups generate no grants; they never become wildcard firewall rules.

## Say “App A can call App B” in Hiera

The relationship is a named entry in `policy.yaml`:

```yaml
profile::policy::connections:
  a_calls_b: {from: app_a, to: app_b, contract: app_api}
```

It selects a published contract and application role mappings from the same file:

```yaml
profile::policy::contracts:
  app_api:
    from_role: api
    to_role: api
    service: api

profile::policy::applications:
  app_a:
    roles:      {web: app_a.web, api: app_a.api, db: app_a.db}
    listeners:  {web: web,       api: api,       db: database}
  app_b:
    roles:      {web: app_b.web, api: app_b.api, db: app_b.db}
    listeners:  {web: web,       api: api,       db: database}

profile::policy::services:
  api:
    protocols: [tcp]
    ports:     [9000]
```

The relationship author knows application names and the contract, not addresses or port numbers. The service owner maintains the API port. The contract narrows the relationship to API callers and API destinations; it does not open all tiers in both applications.

**All four within-application tier relationships are Hiera data too**, using `web_to_api` and `api_to_database` contracts. There are no hard-coded application connection loops in a preprocessor. Delete `a_calls_b` to revoke the cross-application connection at both endpoints. Change the `api` service's port to update every use of that service.

Group-to-group permissions use named services directly:

```yaml
profile::policy::grants:
  users_to_a:     {from: application_users, to: app_a.web,         service: web}
  administration: {from: administrators,    to: application_hosts, service: ssh}
  platform_dns:   {from: application_hosts, to: azure_platform,    service: azure_dns}
```

These are excerpts, not replacement versions of the complete file. Each Hiera policy key uses `merge: first`: replace the complete value when adding a higher-priority layer. Do not deep/unique-merge access lists; doing so can preserve a permission that an override intended to remove.

## What Puppet does with the data

[`profile::policy`](puppet/modules/profile/manifests/policy.pp) receives its parameters through Hiera automatic parameter lookup. It calls the module's [`profile::resolve_policy`](puppet/modules/profile/lib/puppet/functions/profile/resolve_policy.rb) function to validate and resolve groups, contracts and services for `trusted.certname`. The function contains generic resolution and validation logic, not application membership, port or relationship constants.

The result is passed directly to [`profile::host`](puppet/modules/profile/manifests/host.pp), which declares `firewall_multi` resources. Arrays of peer addresses and protocols are expanded by `firewall_multi`. Each endpoint's local address is restricted to its own `/32`, even when its logical group contains multiple nodes. Group-to-group grants intentionally allow the Cartesian product of their members for the selected service.

You can inspect the real Hiera lookup without running any generation command:

```sh
puppet lookup profile::policy::groups      --hiera_config "$PWD/puppet/hiera.yaml" --render-as yaml
puppet lookup profile::policy::connections --hiera_config "$PWD/puppet/hiera.yaml" --explain
```

After importing a fresh snapshot, you can compile directly from the authored hierarchy:

```sh
puppet catalog compile --certname app_a-api --node_name_value app_a-api \
  --manifest "$PWD/puppet/manifests/site.pp" \
  --modulepath "$PWD/puppet/modules:$PWD/vendor" \
  --hiera_config "$PWD/puppet/hiera.yaml" --render-as json
```

The transport/validation helpers do not emit firewall rules or generated per-node Hiera. They package the authored Hiera files unchanged. Puppet performs the actual Hiera lookup and resource compilation on the target.

## Allowed connections and least privilege

| Initiator | Destination | Protocol/port | Reason |
|---|---|---|---|
| `application_users` | A web, B web | TCP 8080 | Application entry points |
| A web | A API | TCP 9000 | Order processing |
| A API | A DB | TCP 15432 | Order data |
| B web | B API | TCP 9000 | Inventory processing |
| B API | B DB | TCP 15432 | Inventory data |
| A API | B API | TCP 9000 | `app_api` contract |
| `administrators` | All six VMs | TCP 22 | Configuration delivery and SSH |
| Each VM | `168.63.129.16` | UDP/TCP 53 | Azure DNS |
| Each VM | `168.63.129.16` | TCP 80, 32526 | Azure guest-agent WireServer |
| Each VM | Azure DHCP/broadcast | UDP 68 -> 67 | Lease acquisition/renewal |
| Azure DHCP | Each VM | UDP 67 -> 68 | DHCP response |

The first nine rows are data-driven named services/grants. DHCP, loopback, invalid-packet rejection and related ICMP errors form the fixed host baseline. INPUT permits only conntrack-RELATED ICMP destination-unreachable, time-exceeded and parameter-problem messages for error reporting/path MTU; unsolicited ping is denied. Forwarding is disabled and FORWARD is DROP. Azure's required platform exceptions are documented by [Microsoft](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16).

There is no blanket `ESTABLISHED,RELATED -> ACCEPT`. Each flow has an ORIGINAL request rule constrained by endpoints and destination ports, and an ESTABLISHED/REPLY rule constrained by endpoints and source ports. Removing the grant removes both; an existing conntrack entry cannot bypass the missing rule. All built-in filter chains purge unmanaged rules, including non-Puppet rules, so removed IPAM members do not retain access. The [`firewall_multi` documentation](https://github.com/alex-harvey-z3q/puppet-firewall_multi) also calls out the need for purging.

Examples denied: users to API/database, web to database, B API initiating to A API, A to B's database, SSH from application VMs, arbitrary Internet HTTP/HTTPS, and unrelated ports on otherwise approved peers. There is no package-download or monitoring egress. Bake dependencies/patches into replacement images and use Azure host PTP time rather than public NTP servers.

## Inject groups from external IPAM

The live highest-priority Hiera document is `puppet/data/external/ipam.json`. It contains **only** `profile::policy::ipam`:

```json
{
  "profile::policy::ipam": {
    "schema_version": 1,
    "revision": "netbox-export-12345",
    "expires_at": "2026-09-21T00:00:00Z",
    "groups": {
      "external.admins": ["10.60.0.10/32"],
      "external.clients": ["10.61.0.0/28"]
    }
  }
}
```

A NetBox/Infoblox adapter on your management runner exports the inner snapshot object (without the Hiera key). The importer validates it against the authored Hiera policy and atomically wraps/publishes it:

```sh
ruby scripts/import_ipam.rb /path/to/vendor-export.json
ruby scripts/validate_data.rb
ruby scripts/make_bundles.rb
```

The implemented integration is a vendor-neutral snapshot boundary, not a vendor-specific API client. Keep IPAM credentials on the runner. No credentials are embedded in Terraform, custom-data or VMs. Do not put live IPAM data in Git. The example date is illustrative; use a fresh export rather than extending the date on stale data.

`groups.yaml` separately defines the reviewed `ipam_scopes`: `external.admins` within `10.60.0.0/24`, and `external.clients` within `10.61.0.0/24`. Change these and memberships to your actual routed networks. Validation requires exactly those external names, canonical CIDRs within their scopes, no overlap with the application VNet, no duplicates, at most 64 entries per group, and a timezone-aware expiry within seven days. IPAM cannot overwrite internal groups, define ports or add contracts.

An empty array means no access. Import is replacement, not additive merge. Failed imports preserve the previous approved snapshot until its lease expires. Missing/expired/invalid snapshots cause Puppet compilation to fail; the runtime wrapper keeps the host quarantined. Under normal scheduling, expiry is enforced on the next timer run, approximately 61 seconds after the preceding run; it is not instantaneous at the timestamp. The same immutable snapshot is checked again before releasing quarantine.

Authenticated transport, a trusted management runner, accurate host time and root-owned data are required. Schema validation does not establish IPAM authenticity. Refresh and deliver snapshots well before expiry. Direct `puppet catalog compile` also validates IPAM, so bypassing the importer does not bypass group-scope/expiry validation.

## Fail-closed boot and updates

A stock VM that downloads/configures its firewall after boot has an exposure window. Terraform therefore requires a prepared Ubuntu image with the pre-network guard already installed.

1. `firewall-quarantine.service` loads a restrictive IPv4 **mangle** table before networking; the network services require it. Only loopback, Azure DHCP and scoped WireServer traffic pass quarantine.
2. Cloud-init writes a bundle containing the authored Hiera documents and starts the apply service asynchronously after cloud-final.
3. The apply wrapper locks, quarantines, copies the bundle into a private temporary directory, validates it, and stages the unchanged Hiera hierarchy. No generated rule data is staged.
4. Puppet reads that hierarchy and installs the **filter** rules. Its purging cannot remove the separate mangle guard. Only exit 0/2 and a fresh lease check release quarantine. The synthetic tier listener then starts.
5. A systemd timer repeats convergence. Every reboot starts in quarantine rather than restoring old permissive rules. Failure leaves/reinstalls quarantine. Bundle delivery shares the same lock and uses an atomic rename.

This intentionally trades availability for fail-closed behaviour: each apply briefly interrupts traffic, including SSH. It is not a zero-downtime controller or a global six-node transaction. Add destination permission before source permission; revoke at the source first. For coordinated cutover, quarantine all affected nodes before applying the new data. A changed demo unit is restarted while quarantined.

This design exclusively owns the IPv4 filter and mangle tables. Do not mix in UFW, firewalld, container networking, NAT, initramfs networking, another persistence service or alternate networking services without redesigning the ownership/boot model. Root/NET_ADMIN remains trusted, and IP-based groups are not application authentication.

## Prepare an image and deploy

Use a disposable Ubuntu 24.04 image builder with cloud-init, the Azure Linux agent, Puppet Agent 8, Python 3, iptables, iproute2, util-linux and working Azure host PTP time. Puppet's bundled Ruby provides the data helper runtime. Use one consistent iptables backend; Ubuntu's iptables-nft compatibility backend is intended. Copy this repository to `/opt/firewall-poc`, excluding credentials, state, `build/` and `.terraform/`.

```sh
cd /opt/firewall-poc
export PATH=/opt/puppetlabs/bin:$PATH
sudo env PATH="$PATH" bash scripts/install_modules.sh
sudo env PATH="$PATH" bash image/prepare.sh
```

Dependencies are pinned to compatible `puppetlabs-firewall` **8.4.0**, `alexharvey-firewall_multi` **8.4.0** and `puppetlabs-stdlib` **9.7.0**. Keep them vendored in the image. `prepare.sh` checks dependencies, disables competing firewall/persistence and Puppet-agent services, and enables the local units. It does not quarantine the builder's active SSH session.

Test boot ordering in an isolated image-test environment. Clean cloud-init identity (`cloud-init clean --logs --machine-id`), run `sudo waagent -deprovision+user -force` on the disposable builder, then deallocate/generalise/capture it from your management runner:

```sh
az vm deallocate --resource-group IMAGE_BUILDER_RG --name IMAGE_BUILDER_VM
az vm generalize --resource-group IMAGE_BUILDER_RG --name IMAGE_BUILDER_VM
az image create --resource-group IMAGE_BUILDER_RG --name firewall-poc-v2 \
  --source IMAGE_BUILDER_VM --hyper-v-generation V2
```

Generalisation is for the disposable builder, not a live application VM. Match image generation to the source VM; a Compute Gallery version is also supported. See [Azure generalisation](https://learn.microsoft.com/en-us/azure/virtual-machines/generalize). Image baking is an explicit prerequisite, not an application Terraform resource. A stock marketplace image does not satisfy the boot guarantee.

From your checkout, import a fresh snapshot and supply subscription ID, prepared image ID and SSH public key:

```sh
ruby scripts/import_ipam.rb /path/to/vendor-export.json
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# Edit the three required values.
az login
terraform -chdir=terraform init
terraform -chdir=terraform validate
terraform -chdir=terraform plan -out=deployment.tfplan
terraform -chdir=terraform apply deployment.tfplan
terraform -chdir=terraform output nodes
```

Terraform reads `inventory.yaml` with `yamldecode` and packages the exact Hiera files into custom-data. It creates the resource group, VNet, three subnets, six NICs and six VMs/disks. No public IP or NAT gateway is created, and default Azure outbound access is disabled. The provider lock file is included.

You must provide existing private routing/peering/VPN from the management/client networks to the new VNet. That connectivity is not created here. Groups must match the source addresses seen at the VM after any external SNAT. Terraform completion does not prove guest success: check `systemctl status firewall-apply.service`, its journal, actual rules and connectivity. Azure provisioning, DHCP renewal, reboot behaviour and PTP need platform acceptance tests.

For data-only changes, send an updated Hiera bundle without replacing the VM:

```sh
ruby scripts/make_bundles.rb
scp build/bundles/app_a-api.json fwadmin@10.42.2.10:bundle.json
ssh fwadmin@10.42.2.10 'sudo /opt/firewall-poc/scripts/install_bundle.sh bundle.json'
```

Deliver the corresponding bundle to every affected node and check convergence. Keep Terraform's source data current too; custom-data changes replace VMs, so review its plan. Existing VMs from the original JSON-preprocessor implementation require a new image or code deployment before using this bundle format. If quarantined, recover via an authenticated serial console or OS-disk attachment, correct the bundle, and rerun the local service. Do not recover by setting policy to ACCEPT. Azure Run Command extensions may require additional storage endpoints and are not assumed to work.

## Verification

```sh
ruby tests/test_policy.rb
puppet parser validate puppet/manifests/site.pp puppet/modules/profile/manifests/*.pp
bash scripts/install_modules.sh
bash scripts/check_catalogs.sh
python3 tests/catalog_mutations.py
terraform -chdir=terraform init -backend=false
terraform -chdir=terraform validate
```

The Ruby tests validate data semantics and the complete request matrix independently of desired rule titles. The catalogue checker copies the authored YAML, uses a short-lived **test-only** IPAM fixture, and compiles all six hosts with the real modules. No live IPAM snapshot is required for those tests. `catalog_mutations.py` edits only Hiera data and recompiles real catalogues to prove contract revocation on both endpoints, named service port changes, IPAM membership replacement and empty-group denial. Catalogues/Facter diagnostics are written under `build/`.

On a disposable Linux VM with Puppet 8, Python, iptables, iproute2 and the pinned modules:

```sh
sudo python3 tests/linux_acceptance.py
```

This applies Puppet directly from the Hiera hierarchy in isolated network namespaces. Listeners deliberately occupy every tested port, so a deny cannot pass through mere connection refusal. It checks 240 network probes, an established session across Hiera contract deletion, and removal of a foreign ACCEPT rule. It uses a temporary bridge/namespaces and does not configure host services/sysctls.

On Azure, additionally verify first boot has no reachable application/SSH window, test ingress and egress separately, remove an IPAM member and a contract while connections are active, inject an unmanaged rule, exercise invalid/expired data, reboot and test recovery. Lease-expiry and systemd behaviour are platform checks, not established by successful catalogue compilation.

**Validation boundary:** local Ruby tests, real Puppet catalogue checks and Terraform validation can run in this macOS environment. Linux packet enforcement and Azure deployment have not been executed here: no Linux/Docker daemon is running and no Azure deployment inputs/image were supplied. No cloud resources have been created. macOS Facter may emit memory-fact diagnostics while catalogue compilation still succeeds.

## Licence

MIT.
