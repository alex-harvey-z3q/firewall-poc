# Two applications, six VMs, host-enforced least privilege

This proof of concept uses Terraform to provision six private Azure Linux VMs and **local Puppet apply** to configure their IPv4 firewalls and synthetic tier services. There is no Puppet server, Azure Firewall, NSG, service mesh, or network firewall in the enforcement path. `puppetlabs/firewall` and `alexharvey/firewall_multi` implement the application rules.

**Default deny applies to INPUT, OUTPUT and FORWARD on every VM.** A named application relationship expands into a specific caller tier, destination service and port. External IPAM supplies bounded address groups; it cannot supply rules or overwrite application identities.

IPv6 is out of scope, as requested. This is an IPv4-only deployment design. The applications are hypothetical: their web, API and database processes are deliberately small HTTP test listeners, including the database tier. They are not a production application, TLS service or actual database.

## Topology

App A is an ordering application; App B is an inventory application. Ordering's API needs to call Inventory's API. Inventory does not need to initiate connections to Ordering.

```text
                   External IPAM (e.g. NetBox / Infoblox)
                          | reviewed JSON snapshot
                          v
    inventory.json + policy.json + bounded external groups
                          |
                    policy compiler
                          |
                 per-host Hiera rule data
                          |
             Puppet -> firewall_multi -> firewall
                          |
                          v
     Azure VNet 10.42.0.0/16 -- private IPs, no public IPs
     +-------------------------------------------------------+
     |       APP A: Ordering       APP B: Inventory            |
     |                                                       |
     |       [A web + FW]           [B web + FW]               |
     |       10.42.1.10            10.42.1.20                 |
     |          | TCP 9000            | TCP 9000              |
     |          v                     v                       |
     |       [A API + FW] --------> [B API + FW]               |
     |       10.42.2.10  TCP 9000   10.42.2.20                |
     |          | TCP 15432           | TCP 15432             |
     |          v                     v                       |
     |       [A DB  + FW]           [B DB  + FW]               |
     |       10.42.3.10            10.42.3.20                 |
     +-------------------------------------------------------+
            ^ TCP 8080 to web VMs only
            |
       external.clients -- existing private routing/VPN

       external.admins  -- TCP 22 to each VM
       each VM          -- exact Azure platform exceptions
       every other NEW network connection: DROP
```

The three tier subnets organize addressing; they do not grant trust. Even hosts sharing a subnet cannot contact one another without a rule. Every application flow needs an OUTPUT grant at its source and an INPUT grant at its destination. Hosts in external groups need their own routing and outbound permissions, which this repository does not manage.

## Allowed connections

| Initiator | Destination | Protocol/port | Reason |
|---|---|---|---|
| `external.clients` | A web, B web | TCP 8080 | Application entry points |
| A web | A API | TCP 9000 | Order processing |
| A API | A DB | TCP 15432 | Order data |
| B web | B API | TCP 9000 | Inventory processing |
| B API | B DB | TCP 15432 | Inventory data |
| A API | B API | TCP 9000 | Named `app_api` contract |
| `external.admins` | All six VMs | TCP 22 | SSH and configuration delivery |
| Each VM | `168.63.129.16` | UDP/TCP 53 | Azure DNS |
| Each VM | `168.63.129.16` | TCP 80, 32526 | Azure guest-agent WireServer |
| Each VM | Azure DHCP/broadcast | UDP 68 -> 67 | Lease acquisition and renewal |
| Azure DHCP | Each VM | UDP 67 -> 68 | DHCP response |

Loopback is permitted. INPUT also admits conntrack-RELATED ICMP destination-unreachable, time-exceeded and parameter-problem messages for network error reporting and path MTU discovery. Unsolicited echo requests are denied. Packet forwarding is disabled and FORWARD is DROP. IP protocol exceptions are limited to the listed needs; application access is not granted by an ICMP exception.

Azure requires the WireServer ports for its guest agent; the special address also provides DHCP and DNS. These exceptions are intentionally separate from application contracts. [Microsoft's platform-address documentation](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16).

Examples of denied traffic: users to either API/database; web to database; A to B's database; B API to A API; SSH from an application VM; arbitrary Internet HTTP/HTTPS; unsolicited reverse connections; and port 9999 even on an otherwise approved destination. No package-download or arbitrary monitoring egress is enabled. Patches and dependencies arrive in replacement images. Time synchronization must use the Azure host's PTP clock in the prepared image rather than public NTP servers.

## Human-readable policy

The business relationship is this entry in `config/policy.json`:

```json
"connections": [
  {"from": "app_a", "to": "app_b", "contract": "app_api"}
]
```

The same file defines `app_api` as caller tier `api`, destination service `api`. The service catalog maps that service to tier `api`, TCP 9000. `config/inventory.json` maps tier membership to private addresses and is also read by Terraform. There is one source of truth for host addresses.

An operator adding a relationship selects application names and a published contract. They need not know the ports or addresses. The service owner maintains the contract. “App A can connect to App B” deliberately does **not** mean every A machine can reach every B machine on every port.

`compile_policy.py` generates source/destination arrays in Hiera. Puppet passes them to `firewall_multi`, which expands them into individual `firewall` resources. Built-in chains purge unmanaged rules, including rules without Puppet comments. This matters when an address disappears from IPAM: addition without purging would retain old access. The module documents that behavior in its [README](https://github.com/alex-harvey-z3q/puppet-firewall_multi).

There is no global `ESTABLISHED,RELATED -> ACCEPT`. Each approved flow has an ORIGINAL rule matching its destination port and an ESTABLISHED/REPLY rule matching its source port, with both endpoint address groups constrained. Removing a flow removes both rules, so existing application connections lose permission too. Conntrack entries themselves can remain; they cannot bypass the missing rule.

## IPAM integration

`config/ipam.example.json` is the vendor-neutral export schema:

```json
{
  "schema_version": 1,
  "revision": "netbox-export-12345",
  "expires_at": "2026-09-21T00:00:00Z",
  "groups": {
    "external.admins": ["10.60.0.10/32"],
    "external.clients": ["10.61.0.0/28"]
  }
}
```

A NetBox/Infoblox adapter runs on the management or CI runner, authenticates using that system's normal secret store, selects approved records/tags, and emits this JSON. No vendor-specific API is assumed, and no IPAM credentials go into Terraform, custom-data or VMs. The implemented integration boundary is a validated snapshot import, not a live vendor API client.

```sh
python3 scripts/import_ipam.py /path/to/ipam-export.json
python3 scripts/compile_policy.py
python3 scripts/make_bundles.py
```

The importer validates the complete snapshot before atomically replacing `config/ipam.json`. Validation requires exactly the approved external group names, canonical IPv4 networks, at most 64 entries per group, no duplicates, no overlap with the application VNet, and each network contained within that group's separately reviewed scope. The example scopes are `10.60.0.0/24` for admins and `10.61.0.0/24` for clients. Change these and the example memberships to your real routed networks before deploying.

An empty array means **no access**, never “any address.” Missing groups, unknown groups, invalid networks, expired snapshots, unknown contracts and invalid topology fail compilation. A snapshot cannot overwrite `app_a-api`, define ports, or grant arbitrary services. The expiry must be timezone-aware, in the future and no more than seven days away.

Import is replacement, not an additive merge. Review `build/resolved-policy.json` and the generated catalog diff before delivery. Scope changes require policy review independently of IPAM. The importer validates bounds, not IPAM authenticity: use authenticated transport, restricted export permissions and a trusted management runner. Root privileges on a target remain a trusted boundary.

Failed imports leave the previous approved snapshot in place until its lease expires. On a host, invalid or expired data causes quarantine. The timer checks approximately every 61 seconds after the preceding run; lease expiry is therefore bounded by that polling interval under normal scheduling, **not instant revocation at the timestamp**. The wrapper checks expiry again before releasing quarantine. The system clock, systemd and root-owned configuration are trusted. Export and deliver refreshed snapshots well before expiry; an IPAM outage must not silently extend leases.

## Fail-closed boot and updates

Starting a stock VM and installing a firewall later leaves a bootstrap exposure window. Consequently Terraform requires a **prepared image**, rather than downloading packages on first boot.

1. The image's `firewall-quarantine.service` loads an IPv4 **mangle** table before the network manager starts. The network services explicitly require its success. Quarantine permits only loopback, Azure DHCP and narrowly scoped WireServer traffic; it blocks SSH and application traffic.
2. Azure cloud-init writes the node's bundle from Terraform custom-data. It starts `firewall-apply.service` asynchronously to avoid a dependency deadlock with cloud-final.
3. The local wrapper takes a lock and reinstalls quarantine before validation or changes. It compiles Hiera and runs Puppet entirely from local files. Puppet owns the **filter** rules; it cannot accidentally remove the separate mangle guard.
4. Only a successful Puppet exit (0 or 2) and a second valid-lease check release the guard. The demo service then starts. Failure retains/reinstalls quarantine; a process killed during convergence leaves the already installed guard in place.
5. A systemd timer repeats convergence. Every reboot starts in quarantine again; the system never restores a previously permissive runtime ruleset before validating current data.

This intentionally trades availability for fail-closed behavior. Each apply briefly interrupts traffic, including SSH; schedule updates accordingly. The example is not a zero-downtime firewall controller. There is no global atomic transaction across six VMs. A changed demo unit is restarted while quarantined; first start happens after release. For coordinated changes, add destination permission before source permission; revoke at the source first, then the destination. A whole-topology cutover can quarantine all nodes before applying the new version.

The image and wrapper exclusively own the IPv4 filter and mangle tables. Do not enable UFW, firewalld, Docker/Kubernetes networking, NAT rules, other rule managers, initramfs networking or alternate networking services without redesigning the boot and ownership model. These VMs are not routers. Root or a process with NET_ADMIN can change the firewall; IP-based groups are not cryptographic application identity. Application authentication remains necessary in a real deployment.

## Build the image

Use a disposable Ubuntu 24.04 Azure image builder with cloud-init and the Azure Linux agent. Install Puppet Agent 8 from your approved artifact source, Python 3, `iptables`, `iproute2`, `util-linux` and a working Azure PTP time configuration. Use one consistent iptables backend; Ubuntu's iptables-nft compatibility backend is the intended target. Ensure the `puppet/resource_api` Ruby library bundled with Puppet is available. Do not install container networking.

Copy this repository to `/opt/firewall-poc` on the builder, excluding `build/`, `.terraform/`, state and credentials. Then:

```sh
cd /opt/firewall-poc
export PATH=/opt/puppetlabs/bin:$PATH
sudo env PATH="$PATH" bash scripts/install_modules.sh
sudo env PATH="$PATH" bash image/prepare.sh
```

The installer pins `puppetlabs-firewall` **8.4.0**, `alexharvey-firewall_multi` **8.4.0**, and `puppetlabs-stdlib` **9.7.0**, matching `Puppetfile`. The firewall modules have explicit compatibility requirements; do not independently upgrade one. Keep dependencies vendored in the image. `prepare.sh` disables competing firewall/persistence and Puppet-agent services and enables the local convergence units, but does not quarantine the builder's current SSH session.

Test the image's first-boot firewall ordering in an isolated image-test environment. Then clean cloud-init identity (`cloud-init clean --logs --machine-id`), deprovision the disposable builder, generalize it and capture a new image version. For example, on the builder run `sudo waagent -deprovision+user -force`; from the management runner:

```sh
az vm deallocate --resource-group IMAGE_BUILDER_RG --name IMAGE_BUILDER_VM
az vm generalize --resource-group IMAGE_BUILDER_RG --name IMAGE_BUILDER_VM
az image create --resource-group IMAGE_BUILDER_RG --name firewall-poc-v1 \
  --source IMAGE_BUILDER_VM --hyper-v-generation V2
```

Deprovision/generalize is for a disposable builder and makes it unsuitable for continued normal use. Choose image generation consistent with your source VM; a Compute Gallery image version is also supported through `image_id`. See [Azure image generalization](https://learn.microsoft.com/en-us/azure/virtual-machines/generalize).

Image baking/capture is an explicit prerequisite, not an image resource managed by the supplied application Terraform. The image must contain the boot guard; substituting a marketplace image defeats the first-boot guarantee.

## Provision the six VMs

Prerequisites: Terraform 1.6+, an Azure subscription/login or workload identity, permission to create resources, the prepared image ID, an SSH public key, and private connectivity from the approved admin/client networks. The example creates a new VNet; connect it to your existing routed hub/VPN using your normal peering/routing configuration. That connectivity is a prerequisite and is not created here. The host policy uses the source IP actually observed by the VM; account for any existing SNAT when selecting IPAM groups.

```sh
# From the repository root, validate a fresh real IPAM export first.
python3 scripts/import_ipam.py /path/to/ipam-export.json
python3 scripts/compile_policy.py
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# Edit subscription_id, image_id and ssh_public_key.
az login
terraform -chdir=terraform init
terraform -chdir=terraform validate
terraform -chdir=terraform plan -out=deployment.tfplan
terraform -chdir=terraform apply deployment.tfplan
terraform -chdir=terraform output nodes
```

Terraform creates a resource group, VNet, three subnets, six NICs, six VMs and their OS disks. There are no public IPs or NAT gateways. Default Azure outbound access is disabled. Each VM receives its full reviewed bundle through custom-data. The provider lock file is included. [AzureRM's VM resource](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine) documents the image and custom-data interfaces.

Terraform success alone is not proof of guest configuration success. Check `systemctl status firewall-apply.service`, `journalctl -u firewall-apply.service`, the actual rules and connectivity before accepting a deployment. A bad image or bundle should result in inaccessible application ports, not relaxed permissions. Azure provisioning/guest-agent completion, DHCP renewal, boot ordering, PTP and reboot behavior still need validation on Azure.

The sample IPAM date is an example, not a perpetual lease. Do not automate refreshing the timestamp on old data. Terraform custom-data changes replace VMs; review the plan. For routine IPAM changes use the existing admin path to deliver a validated bundle locally without replacing a VM:

```sh
python3 scripts/make_bundles.py
scp build/bundles/app_a-api.json fwadmin@10.42.2.10:bundle.json
ssh fwadmin@10.42.2.10 'sudo /opt/firewall-poc/scripts/install_bundle.sh bundle.json'
```

Repeat for the other five VMs with the corresponding bundles; check each run. The installer holds the same lock as convergence and atomically renames the bundle. Each apply uses an immutable copy, so a concurrent delivery cannot mix policies or lease checks. Update the source snapshot used by Terraform too, so a replacement gets current data. SSH/NET_ADMIN is a trusted management privilege, not available to the demo processes. If already quarantined, use an authenticated serial-console recovery procedure or attach the OS disk to a recovery VM; replace the bad bundle and rerun the local service. Do not recover by setting policies to ACCEPT. Azure Run Command extensions may need additional storage endpoints and are not assumed to work under this minimal policy.

## Verification

Local static/data checks:

```sh
python3 -m unittest discover -s tests -v
puppet parser validate puppet/manifests/site.pp puppet/modules/profile/manifests/host.pp
bash scripts/install_modules.sh
# Requires a valid config/ipam.json:
bash scripts/check_catalogs.sh
terraform -chdir=terraform init -backend=false
terraform -chdir=terraform validate
```

The catalog checker compiles all six hosts using the real pinned modules, checks DROP policies and purging, and verifies that `firewall_multi` expanded address arrays. It does not apply rules to the development machine. Catalogs and per-node Facter diagnostics are under `build/`.

On a **disposable Linux test VM**, install Puppet 8, Python, iptables and iproute2, vendor the pinned modules, then run:

```sh
sudo python3 tests/linux_acceptance.py
```

This test uses real Puppet providers in separate network namespaces. It puts listeners on every tested port, then checks 240 positive/negative source/destination/port combinations (including admin, client and untrusted hosts), a TCP session held across contract revocation, and deletion of a foreign ACCEPT rule. It avoids configuring host services/sysctls. It changes a temporary bridge and namespaces, so use a dedicated test VM rather than a workstation or production host.

Azure acceptance checklist:

- Observe first boot with no window of reachable SSH/app ports before successful configuration.
- Verify the allowed matrix and forbidden examples against actual private VM addresses; test both OUTPUT and INPUT using a probe host with the opposite side permissive.
- Remove a contract and an IPAM member, reapply to affected hosts, and test new **and already established** connections.
- Inject an unmanaged accept rule, reapply, and confirm removal.
- Submit empty, malformed, out-of-scope and expired IPAM data. Confirm empty groups grant nothing and invalid local bundles retain quarantine.
- Reboot; verify DROP policies, no forwarding, DNS/DHCP/WireServer health, service recovery and accurate host time.
- Observe snapshot expiry and loss of management access; exercise console/disk recovery before relying on it operationally.

Validation performed in the development environment: the Python policy tests, Puppet parser checks, six real module catalog compilations and Terraform provider validation. Linux packet-level and Azure deployment tests have **not** been executed here; this macOS environment has no running Docker/Linux daemon, and no deployment image or Azure subscription inputs were supplied. Local Facter produced macOS memory-fact diagnostics; catalog compilation and resource assertions nevertheless succeeded. No cloud resources were created.

## Repository map

| Path | Purpose |
|---|---|
| `config/inventory.json` | Shared Terraform/policy node addresses |
| `config/policy.json` | Service contracts, app relationships, IPAM scope boundaries |
| `config/ipam.example.json` | External IPAM snapshot example |
| `scripts/compile_policy.py` | Validating policy compiler, Hiera and resolved-policy output |
| `scripts/import_ipam.py` | Atomic validated snapshot import |
| `scripts/make_bundles.py`, `scripts/install_bundle.sh` | Per-host payloads and serialized atomic activation |
| `puppet/modules/profile/manifests/host.pp` | Default-deny chains, exceptions, expanded rules, host configuration |
| `scripts/apply.sh`, `image/` | Fail-closed boot, update guard, local Puppet timer, image preparation |
| `terraform/` | Six private Azure VMs and supporting network resources |
| `tests/` | Policy validation and Linux enforcement acceptance tests |
