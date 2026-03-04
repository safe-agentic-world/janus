# Nomos Helm Chart

This chart provides the minimal Kubernetes install path for Nomos quickstart and evaluation deployments.

## Safe Defaults

Default values install a working demo deployment with:

- a starter in-chart policy bundle
- demo API key auth
- `stdout` audit sink
- `ClusterIP` service on port `8080`

The defaults are intended for evaluation, not production hardening.

## Security-Sensitive Values

- `identity.useDemoCredentials`
- `identity.apiKey`
- `identity.agentSecret`
- `identity.oidc.*`
- `audit.sink`
- `config.useStarterBundle`
- `config.policyBundlePath`

## Fail-Closed Behavior

If you disable demo credentials and omit `identity.apiKey` or `identity.agentSecret`, the chart renders a warning object and does not render the `Deployment`.

If you disable the starter bundle and omit `config.policyBundlePath`, the chart renders a warning object and does not render the `Deployment`.

## Example

```powershell
helm template nomos .\deploy\helm\nomos -f .\deploy\helm\nomos\values.example.yaml
```
