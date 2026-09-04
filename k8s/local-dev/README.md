# k8s/local-dev — local microk8s only, never part of a chart or a release

`stub-crds.yaml` registers permissive stand-ins for the `CiliumNetworkPolicy`
and `TracingPolicy(Namespaced)` CRDs so a local microk8s cluster without the
real Cilium/Tetragon operators installed can still accept the security-baseline
resources every `k8s/helm/*` chart renders. Apply it once, by hand, before a
local first-run deploy — `kubectl apply -f k8s/local-dev/stub-crds.yaml` — it
is not referenced by any chart and must never be. Beta/gamma/prod run the real
operators and must never see this file.
