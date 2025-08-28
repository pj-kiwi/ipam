# IPAM for WordPress — Complete Setup & Operations Guide

This single file contains **end‑to‑end instructions** to deploy, configure, and operate the IPAM WordPress plugin and the optional Alta Route10 LAN collector.

> Works with WordPress 6.x+, PHP 7.4+ (PHP 8 recommended)

---

## 1) What you get

- **IPAM WordPress plugin** providing:
  - Subnet management (CIDR), IP allocations, and a request workflow (users request; admins approve/reject)
  - WordPress RBAC: administrators manage, standard users can request
  - Admin UI pages: **IPAM → Subnets**, **IPAM → Requests**
  - Shortcode for end‑users: `[ipam_request subnet_id="<ID>"]`
  - REST endpoint for DHCP events: `POST /wp-json/ipam/v1/event`
- **Alta Route10 collector** (Python): scans ARP/ND on your LAN (behind the Route10), does optional reverse DNS (PTR), and posts events to your site

---

## 2) Prerequisites

- A running WordPress site with HTTPS
- Admin access to upload/activate plugins
- For the collector: a Linux host on the LAN (e.g., Ubuntu Server) with Python 3.9+

---

## 3) Plugin installation

1. In WordPress Admin, go to **Plugins → Add New → Upload Plugin**.
2. Upload the provided ZIP (e.g., `ipam_wp.zip`).
3. Click **Activate**.
4. On activation the plugin creates tables:
   - `wp_ipam_subnets`
   - `wp_ipam_ips`
   - `wp_ipam_requests`

> If you use a custom DB prefix, table names will include your prefix. If activation was interrupted, deactivate & activate again.

---

## 4) Roles & permissions

The plugin adds capabilities:
- `manage_ipam`, `approve_ip_requests` → granted to **administrator**
- `request_ip` → granted to **subscriber**, **editor**, and **administrator**

Adjust roles with a role editor plugin if needed.

---

## 5) Basic configuration & usage

### 5.1 Add a subnet
1. Go to **IPAM → Subnets**.
2. Enter CIDR, e.g., `192.168.10.0/24` (IPv4). Optional: Name, Description.
3. Click **Create**.

> The system does not pre‑populate every IP; it allocates on demand. “Next free” computes by diffing existing allocations against the host range.

### 5.2 Create an end‑user request page
1. Create a WordPress page (e.g., **Request an IP**).
2. Add the shortcode:
   ```
   [ipam_request subnet_id="<SUBNET_ID>"]
   ```
   Replace `<SUBNET_ID>` with the numeric ID from **IPAM → Subnets**.
3. Publish the page. Users must be logged in and have the `request_ip` capability.

### 5.3 Approving requests
- Navigate to **IPAM → Requests**.
- **Approve**: allocates the specified IP or next free in the subnet and creates an `ipam_ips` row.
- **Reject**: marks the request rejected. (Optional admin comment field is available in the code path.)

---

## 6) REST endpoint (for DHCP events)

- **Endpoint**: `POST /wp-json/ipam/v1/event`
- **Auth**: Recommended is **Application Passwords** (WordPress built‑in). Create an Application Password for a user with `manage_ipam`.
  - Go to **Users → Profile** → **Application Passwords** → add a new one and copy the generated value.
- **Payload**:
  ```json
  {
    "events": [
      {"ip":"192.168.1.23","mac":"aa:bb:cc:dd:ee:ff","hostname":"host"}
    ]
  }
  ```
- The plugin finds a matching subnet (by CIDR) and creates an **assigned** allocation if it does not already exist.

### 6.1 Quick test with curl
```bash
SITE="https://your-site.example"
USER="ipamadmin"
APP_PASS="xxxx xxxx xxxx xxxx"   # Application Password
curl -X POST "$SITE/wp-json/ipam/v1/event" \
  -u "$USER:$APP_PASS" \
  -H 'Content-Type: application/json' \
  -d '{"events":[{"ip":"192.168.10.25","mac":"aa:bb:cc:dd:ee:ff","hostname":"host1"}]}'
```

---

## 7) Alta Route10 collector (optional, recommended)

The collector runs on a Linux LAN host and:
- Scans ARP/neighbor tables for active clients (works vendor‑agnostic; Route10 is the LAN DHCP server by default)
- Optionally performs **reverse DNS (PTR)** lookups to fill hostnames
- Posts events to your WordPress site’s REST endpoint

### 7.1 Install on Linux
```bash
# on a LAN host (Ubuntu example)
mkdir -p ~/ipam-collector && cd ~/ipam-collector
# copy the provided collector script here as alta_route10_collector.py
python3 -m venv .venv
source .venv/bin/activate
pip install dnspython
```

### 7.2 Configure environment
```bash
export WP_BASE="https://your-site.example"     # your WordPress base URL
export WP_USER="ipamadmin"                     # a WP user with manage_ipam
export WP_APP_PASS="abcd abcd abcd abcd"       # Application Password
# DNS options (optional)
export DNS=1                                    # enable PTR lookups (default 1)
export DNS_RESOLVER="192.168.10.1,1.1.1.1"     # local resolver(s), optional
export DNS_TIMEOUT=1.0                          # seconds per DNS question
export DNS_MAX=100                              # max DNS questions per run
```

### 7.3 Run manually
```bash
auth python3 alta_route10_collector.py
```
You should see `POST 201 {"created": ... }` for newly discovered clients.

### 7.4 Run on a schedule (systemd timer)
Create `~/.config/systemd/user/ipam-collector.service`:
```ini
[Unit]
Description=IPAM WordPress Alta Route10 Collector
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=%h/ipam-collector
ExecStart=%h/ipam-collector/.venv/bin/python %h/ipam-collector/alta_route10_collector.py
Environment=WP_BASE=https://your-site.example
Environment=WP_USER=ipamadmin
Environment=WP_APP_PASS=abcd abcd abcd abcd
Environment=DNS=1
Environment=DNS_RESOLVER=192.168.10.1
Environment=DNS_TIMEOUT=1.0
Environment=DNS_MAX=80
```

Create `~/.config/systemd/user/ipam-collector.timer`:
```ini
[Unit]
Description=Run IPAM collector every minute

[Timer]
OnCalendar=*-*-* *:*:00
AccuracySec=10s
Persistent=true

[Install]
WantedBy=timers.target
```
Enable timer:
```bash
systemctl --user daemon-reload
systemctl --user enable --now ipam-collector.timer
journalctl --user -u ipam-collector.service -f
```

> On servers without lingering for user services, use system‑level units in `/etc/systemd/system/` instead (change `WorkingDirectory`, paths, and `User=` accordingly).

---

## 8) Security best practices

- **HTTPS only** for the site and collector REST calls
- Use **Application Passwords** for the collector and store them securely
- Restrict the collector host with firewall rules (egress only to your site)
- Review role assignments; only trusted users should have `manage_ipam`
- Back up WordPress DB regularly (the IPAM data lives in custom tables)

---

## 9) Troubleshooting

**I still see no IPs after running the collector**
- Verify the REST endpoint with `curl` (see §6.1) — must return 201
- Make sure the IP falls inside a configured subnet
- Check WordPress error logs (hosting panel or `WP_DEBUG_LOG`)

**Shortcode says I must log in**
- Ensure the page requires login (use a membership plugin or put the page behind login)
- Confirm the user role has `request_ip`

**PTR lookups are slow**
- Lower `DNS_MAX` and `DNS_TIMEOUT`; use a fast local resolver

**Plugin didn’t create tables**
- Deactivate and activate again (WordPress runs `dbDelta()` on activation)

**Permalink/REST issues**
- Ensure your site exposes `/wp-json` (pretty permalinks enabled). If not, use default permalinks; the REST API should still be reachable.

---

## 10) Data model (reference)

- **Subnets**: `id`, `name`, `cidr`, `description`, `created_at`
- **IPs**: `id`, `subnet_id`, `ip`, `hostname`, `status`, `assigned_to`, `notes`, `created_at`, `updated_at` (unique per `(subnet_id, ip)`)
- **Requests**: `id`, `subnet_id`, `user_id`, `mode (next_free|specific)`, `ip?`, `hostname`, `assigned_to`, `notes`, `status`, `admin_comment`, `created_at`, `updated_at`

---

## 11) Extending the plugin (ideas)

- Front‑end tables (shortcodes) to list allocations by subnet
- CSV import/export; bulk reserve; search filters
- Email/Slack notifications on request submit/approval
- IPv6 helpers for CIDR math and validation
- Token‑based auth for the REST endpoint (if not using App Passwords)

---

## 12) Quick reference (commands)

```bash
# Upload & activate plugin in WP admin
# Create subnet(s) in IPAM → Subnets
# Create a request page with shortcode [ipam_request subnet_id="1"]

# Collector (Linux)
python3 -m venv .venv && source .venv/bin/activate
pip install dnspython
export WP_BASE="https://your-site.example" WP_USER="ipamadmin" WP_APP_PASS="abcd abcd abcd abcd"
python alta_route10_collector.py

# Test REST
curl -X POST "$WP_BASE/wp-json/ipam/v1/event" -u "$WP_USER:$WP_APP_PASS" \
  -H 'Content-Type: application/json' -d '{"events":[{"ip":"192.168.10.20","mac":"00:11:22:33:44:55","hostname":"host20"}]}'
```

---

**That’s it!** If you want, I can package this guide into your plugin ZIP as `README.md`, or tailor a systemd unit for your specific host.
