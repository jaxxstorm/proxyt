# High Availability

To run ProxyT with high availability, run **multiple independent instances behind
a compatible load balancer**, all configured with the same public hostname.
Instances can run as binaries, containers, or orchestrated workloads. Kubernetes
is one deployment option, not a requirement.

```text
                 proxy.example.com
                         |
              Highly available load balancer
                  /      |      \
             ProxyT   ProxyT   ProxyT
                  \      |      /
                Tailscale control plane
```

Place instances on separate hosts or failure domains if they must survive host
failure. Allow enough capacity on the remaining instances for clients to
reconnect when one disappears. The frontend must also be highly available;
a single unmanaged load-balancer process remains a single point of failure.

## Load-balancer requirements

**TCP forwarding with TLS passthrough is the simplest configuration.** Forward
public port 443 to each instance's TLS listener. The load balancer must preserve
each TCP stream without interpreting its contents.

For an HTTP frontend that terminates TLS instead:

- Preserve the original `/ts2021` request method, including `POST`.
- Forward `Connection: Upgrade` and the nonstandard `Upgrade` token unchanged.
- Use HTTP/1.1 for the upgrade path to ProxyT.
- Forward `101 Switching Protocols` and then relay bytes in both directions.
- Do not buffer, rewrite, or impose a short request timeout on upgraded streams.

Standard WebSocket support alone is insufficient. A frontend that rejects the
upgrade cannot be made compatible by changing ProxyT. See the
[hosting compatibility matrix](hosting.md#compatibility-matrix).

For either mode:

- Keep an established connection on its selected backend. Sticky sessions across
  separate connections are unnecessary; replicas share no session database.
- Remove unhealthy or draining instances from selection for new connections.
- Preserve existing streams during planned backend deregistration where the
  frontend supports it.
- Configure idle and connection-lifetime limits for long-lived control streams.
  Check the settings for the actual TCP/upgrade mode; an HTTP timeout setting
  might not apply to TLS passthrough.
- Leave PROXY protocol disabled: ProxyT does not parse PROXY protocol headers.
- Point DNS at the frontend. If using Cloudflare DNS, use a DNS-only record,
  not Cloudflare's HTTP proxy.

## TLS and instance configuration

### TLS passthrough

Provision a valid certificate for the public hostname on every instance using an
external certificate manager. Mount the certificate directory read-only and run:

```sh
proxyt serve \
  --domain=proxy.example.com \
  --issue=false \
  --cert-dir=/etc/proxyt/certs \
  --https-port=8443 \
  --port=8080
```

The load balancer forwards TCP port 443 to port 8443 on each host. The certificate
directory must contain `proxy.example.com.crt` and `proxy.example.com.key`.
Port 8080 serves redirects and need not be publicly exposed for this setup.

ProxyT polls external certificate files every 30 seconds and atomically loads a
valid replacement without interrupting existing tunnels. Invalid replacements
retain the last successfully loaded pair and are retried. If that active
certificate expires, readiness fails. Initial certificates must be valid for the
configured hostname. Mount directories rather than individual file inodes so
atomic replacements remain visible.

Do not run independent built-in ACME issuers behind a shared frontend for HA.
Challenges can reach the wrong instance, and a shared certificate directory does
not coordinate issuance. Use external issuance, such as DNS-01, and distribute
the resulting certificate files.

### TLS termination at the frontend

Let the frontend manage the public certificate and run each instance on a private
backend network:

```sh
proxyt serve --domain=proxy.example.com --http-only --port=8080
```

Forward to port 8080 using the HTTP upgrade requirements above. The public
hostname remains HTTPS; `--http-only` describes the backend listener.

## Health checks, shutdown, and recovery

- **`/health`**: local liveness; does not check Tailscale connectivity.
- **`/ready`**: serving readiness; checks upstream reachability and any locally
  managed TLS certificate. Returns 503 as soon as draining begins. Its upstream
  check has a five-second timeout, so allow longer than that for the probe.
- **`/metrics`**: scrape each instance separately to observe active tunnels,
  upstream errors, certificate expiry, reload outcomes, and draining state.

Use readiness to control new backend selection, and liveness for process
restarts. When a platform load balancer targets hosts rather than individual
instances, retain its platform-managed health checks and use instance readiness
to control the endpoints behind those hosts.

On SIGTERM or SIGINT, ProxyT:

1. Becomes unready and rejects new proxy requests with 503.
2. Keeps listeners open for `--shutdown-delay` (default **5s**) so routing changes
   can propagate. Existing tunnels continue.
3. Closes listeners and waits for admitted requests and tunnels under one shared
   `--shutdown-timeout` budget (default **25s**).
4. Closes any remaining connections and exits.

Give the process manager more than the delay plus timeout, with cleanup margin;
**45 seconds** accommodates the defaults. Ensure containers receive SIGTERM
instead of being killed immediately. Pace rolling replacements so clients can
reconnect before the next instance is removed.

An existing tunnel cannot migrate to another instance. When its instance exits
or crashes, the client establishes a new connection through the frontend. Peer
traffic may continue during a control-plane interruption, so successful pings
alone do not prove control recovery. Check client control logs and fresh peer-map
updates as well.

Adding instances only distributes **new** connections. Existing long-lived
tunnels do not automatically rebalance. The metrics listener closes during
shutdown before forced tunnel cleanup; use lifecycle logs for final shutdown
counts.

See [configuration](configuration.md) for timeout and reload settings. Use an
image containing HA support; `ghcr.io/jaxxstorm/proxyt:ha` is the experimental
build. Pin a tested version or digest for production.

## Example: Kubernetes

The repository includes
[`deploy/kubernetes/ha.yaml`](https://github.com/jaxxstorm/proxyt/blob/main/deploy/kubernetes/ha.yaml).
It demonstrates the same architecture with a Deployment and a TCP LoadBalancer
Service:

- Three replicas on distinct workers using required pod anti-affinity.
- TLS terminated in ProxyT with an externally managed Secret.
- Readiness, liveness, and startup probes.
- A 45-second termination grace period and a disruption budget keeping two
  replicas available during voluntary evictions.

### 1. Prepare the example

Use your intended `kubectl` context. The example requires at least **three
schedulable workers**. For a single-worker trial, relax anti-affinity, understanding
that multiple pods on one worker do not protect against worker failure.

Replace `proxy.example.com` in the domain argument and certificate volume paths.
Choose an appropriate image tag/digest. Add provider-specific Service annotations
that explicitly select TCP forwarding or TLS passthrough; `protocol: TCP` in a
Kubernetes Service does not by itself specify every cloud frontend setting.

For example, DigitalOcean's regional TCP configuration uses these annotations
under the Service's `metadata`:

```yaml
annotations:
  service.beta.kubernetes.io/do-loadbalancer-type: REGIONAL
  service.beta.kubernetes.io/do-loadbalancer-protocol: tcp
  service.beta.kubernetes.io/do-loadbalancer-enable-proxy-protocol: "false"
```

The Service uses `externalTrafficPolicy: Local`. Let the cloud controller manage
node health checks; pod readiness controls eligible endpoints. Check your
provider's deregistration and idle-timeout behavior for the selected mode.

### 2. Supply a certificate

Create the namespace before either certificate option:

```sh
kubectl create namespace proxyt
```

For an externally issued certificate:

```sh
kubectl -n proxyt create secret tls proxyt-tls \
  --cert=/path/to/fullchain.pem --key=/path/to/privkey.pem
```

Alternatively, use cert-manager with an existing DNS-01 ClusterIssuer. Replace
the hostname and issuer name, then apply this Certificate in namespace `proxyt`:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: proxyt-tls
  namespace: proxyt
spec:
  secretName: proxyt-tls
  dnsNames:
    - proxy.example.com
  issuerRef:
    name: letsencrypt-dns
    kind: ClusterIssuer
```

Configure the issuer and DNS credentials separately for your DNS provider.
Do not manually create the TLS Secret when cert-manager owns it. The example
mounts the Secret directory without `subPath`, allowing Kubernetes Secret updates
to reach ProxyT's certificate poller.

### 3. Deploy and configure DNS

```sh
kubectl apply -f deploy/kubernetes/ha.yaml
kubectl -n proxyt rollout status deployment/proxyt-ha
kubectl -n proxyt get service proxyt-ha
```

Point the public hostname to the Service's external address, then verify:

```sh
curl --fail https://proxy.example.com/ready
tailscale up --login-server=https://proxy.example.com
```

Run clients through the real frontend before relying on the configuration: a
successful readiness request does not verify the `/ts2021` upgrade path.

### 4. Observe a replica replacement

With test clients connected, collect per-pod metrics and timestamped client/pod
logs. Select a pod that has active tunnels, then delete it normally:

```sh
kubectl -n proxyt get pods -l app=proxyt-ha
kubectl -n proxyt delete pod <selected-pod>
kubectl -n proxyt rollout status deployment/proxyt-ha
```

Confirm that the selected pod drains, clients reconnect through healthy
instances, and fresh control-plane updates arrive. Test host failure separately
if that is part of your availability requirement. A disruption budget limits
voluntary evictions; it does not prevent crashes or direct pod deletion.
