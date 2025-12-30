# Helm Chart

ProxyT provides official Helm charts for Kubernetes deployment.

## Quick Start

```bash
# Install from OCI registry
helm install proxyt oci://ghcr.io/jaxxstorm/charts/proxyt \
  --set proxyt.domain=proxy.example.com \
  --set proxyt.email=admin@example.com
```

## Deployment Scenarios

### 1. Standalone with Let's Encrypt

```bash
helm install proxyt oci://ghcr.io/jaxxstorm/charts/proxyt \
  --set proxyt.domain=proxy.example.com \
  --set proxyt.email=admin@example.com \
  --set service.type=LoadBalancer
```

### 2. Behind Ingress Controller

```bash
helm install proxyt oci://ghcr.io/jaxxstorm/charts/proxyt \
  --set proxyt.domain=proxy.example.com \
  --set proxyt.httpOnly=true \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set 'ingress.hosts[0].host=proxy.example.com'
```

### 3. With cert-manager

```bash
helm install proxyt oci://ghcr.io/masterbpro/charts/proxyt \
  --set proxyt.domain=proxy.example.com \
  --set certManager.enabled=true \
  --set certManager.issuer.name=letsencrypt-production
```

### 4. Production Setup

```bash
helm install proxyt oci://ghcr.io/masterbpro/charts/proxyt -f values-production.yaml
```

### 5. From GitHub Release

```bash
helm install proxyt https://github.com/masterbpro/proxyt/releases/download/proxyt-1.0.1/proxyt-1.0.1.tgz \
  --set proxyt.domain=proxy.example.com \
  --set proxyt.email=admin@example.com
```

**values-production.yaml:**

```yaml
replicaCount: 3

proxyt:
  domain: "proxy.example.com"
  email: "admin@example.com"
  httpOnly: true

service:
  type: ClusterIP

ingress:
  enabled: true
  className: "nginx"
  hosts:
    - host: proxy.example.com
      paths:
        - path: /
          pathType: Prefix

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10

podDisruptionBudget:
  enabled: true
  minAvailable: 2
```

## Configuration

### Required Parameters

| Parameter       | Description                                 |
|-----------------|---------------------------------------------|
| `proxyt.domain` | Your domain name                            |
| `proxyt.email`  | Email for Let's Encrypt (when `issue=true`) |

### Common Parameters

| Parameter             | Default     | Description            |
|-----------------------|-------------|------------------------|
| `replicaCount`        | `1`         | Number of replicas     |
| `proxyt.httpOnly`     | `false`     | Run behind HTTPS proxy |
| `proxyt.debug`        | `false`     | Enable debug logging   |
| `service.type`        | `ClusterIP` | Service type           |
| `ingress.enabled`     | `false`     | Enable ingress         |
| `autoscaling.enabled` | `false`     | Enable HPA             |

See [full documentation](../charts/proxyt/README.md) for all parameters.

## Verify Installation

```bash
# Check pods
kubectl get pods -l app.kubernetes.io/name=proxyt

# View logs
kubectl logs -l app.kubernetes.io/name=proxyt -f

# Test health endpoint
kubectl port-forward svc/proxyt 8080:80
curl http://localhost:8080/health
```

## Upgrade

```bash
helm upgrade proxyt oci://ghcr.io/masterbpro/charts/proxyt \
  --set proxyt.domain=proxy.example.com \
  --set proxyt.email=admin@example.com
```

## Uninstall

```bash
helm uninstall proxyt
```
