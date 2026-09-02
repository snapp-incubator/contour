# Per-Route Authorization Override for HTTPProxy

## Abstract

This document proposes adding support for a list of named authorization providers at the `VirtualHost` level in
`HTTPProxy` and allowing individual routes to reference them by name using `authPolicy.require`. This pattern matches
the existing `JWTProviders` implementation and enables multi-provider external authorization configurations without
modifying Envoy filter generation mechanics.

## Background

Currently, Contour supports configuring external authorization at the `VirtualHost` level using the`authorization` field
(`AuthorizationServer`). In scenarios where different routes under the same virtual host require different external
authorization services (e.g. different auth backends for billing, admin, and public routes), configuring full auth
violates DRY principles. Contour already adopted a named provider pattern for JWT verification
(`virtualhost.jwtProviders` and route-level `jwtVerificationPolicy.require`).

## Goals

- Allow defining a list of named `authorizationProviders` on `HTTPProxy.spec.virtualhost`.
- Allow marking at most one provider as `default: true` to automatically apply to routes without an explicit
  requirement.
- Allow individual routes to reference a named provider via `authPolicy.require`.
- Maintain backward compatibility by supporting and deprecating the singular `virtualhost.authorization` field.

## Non Goals

- Modify Envoy's HTTP connection manager filter architecture or introducing custom Envoy filter logic.
- Support non-TLS-terminating virtual hosts.

## High-Level Design

At the `VirtualHost` level, a new field `authorizationProviders` is added as a list of `AuthorizationProvider` structs.
Each provider has a mandatory `name`, an optional `default` boolean flag, and standard external authorization settings.

In individual routes, `authPolicy` is extended with a new field `require: <provider-name>`. When DAG building occurs:

1. The DAG processor validates the provider list (ensuring uniqueness of names, at most one default provider, and valid
   references).
2. For each route, the effective authorization provider is resolved (either explicit `require`, the default provider, or
   disabled if `disabled: true`).
3. The existing route-level Envoy config generation applies `ExtAuthzPerRoute` override settings as needed.

## Detailed Design

### API Changes

In `apis/projectcontour/v1/httpproxy.go`:

```go
package v1

type VirtualHost struct {
	// ... existing fields ...

	// Authorization configures external authorization for the virtual host.
	// Deprecated: Use AuthorizationProviders instead.
	// +optional
	Authorization *AuthorizationServer `json:"authorization,omitempty"`

	// AuthorizationProviders defines a list of named authorization providers
	// that can be referenced by routes in this VirtualHost.
	// +optional
	AuthorizationProviders []AuthorizationProvider `json:"authorizationProviders,omitempty"`

	// ... other fields ...
}

// AuthorizationProvider defines a named external authorization service.
type AuthorizationProvider struct {
	// Name is a unique identifier for the authorization provider within this VirtualHost.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Default indicates whether this provider applies to all routes that do not
	// explicitly specify a provider or disable authorization.
	// At most one provider in authorizationProviders can be marked as default.
	// +optional
	Default bool `json:"default,omitempty"`

	// ExtensionServiceRef specifies the extension resource that will authorize client requests.
	// +kubebuilder:validation:Required
	ExtensionServiceRef ExtensionServiceReference `json:"extensionRef"`

	// ServiceType defines the protocol used to communicate with the authorization server.
	// Defaults to "grpc".
	// +optional
	// +kubebuilder:validation:Enum=http;grpc
	// +kubebuilder:default=grpc
	ServiceType AuthorizationServiceType `json:"serviceType,omitempty"`

	// HTTPServerSettings defines configurations for interacting with an external HTTP authorization server.
	// Only valid when ServiceType is "http".
	// +optional
	HTTPServerSettings *HTTPAuthorizationServerSettings `json:"httpSettings,omitempty"`

	// ResponseTimeout configures the maximum time to wait for a check response.
	// +optional
	// +kubebuilder:validation:Pattern=`^(((\d*(\.\d*)?h)|(\d*(\.\d*)?m)|(\d*(\.\d*)?s)|(\d*(\.\d*)?ms)|(\d*(\.\d*)?us)|(\d*(\.\d*)?µs)|(\d*(\.\d*)?ns))+|infinity|infinite)$`
	ResponseTimeout string `json:"responseTimeout,omitempty"`

	// FailOpen specifies whether to allow traffic if the auth server fails or is unreachable.
	// +optional
	FailOpen *bool `json:"failOpen,omitempty"`

	// WithRequestBody specifies configuration for sending the client request's body to the authorization server.
	// +optional
	WithRequestBody *AuthorizationServerBufferSettings `json:"withRequestBody,omitempty"`
}

type AuthorizationPolicy struct {
	// When true, this field disables client request authentication for the scope of the policy.
	// +optional
	Disabled bool `json:"disabled,omitempty"`

	// Require specifies the name of the AuthorizationProvider defined on the VirtualHost to use for this route.
	// If omitted and a default provider is configured on the VirtualHost, the default provider is used.
	// +optional
	Require string `json:"require,omitempty"`

	// Context is a set of key/value pairs that are sent to the authentication server in the check request.
	// +optional
	Context map[string]string `json:"context,omitempty"`
}
```

### Validation & DAG Processing

1. **VirtualHost Validation**:
    - `authorization` and `authorizationProviders` cannot both be specified on the same `VirtualHost`.
    - Provider `name` values within `authorizationProviders` must be unique.
    - At most one provider in `authorizationProviders` may have `default: true`.
    - If `serviceType` is `grpc`, `httpSettings` must not be set.

2. **Route Validation & Resolution**:
    - If a route has `authPolicy.disabled: true` and `authPolicy.require` is specified, it is an error.
    - If `authPolicy.require` is specified, a provider with that name must exist in the root
      `VirtualHost.authorizationProviders`. If not found, a validation error condition is added to the `HTTPProxy`.
    - If a route does not set `authPolicy.require` and `authPolicy.disabled` is not true:
        - If a provider is marked `default: true`, that provider is selected.
        - If no default provider exists, authorization is not enabled for the route (or retains parent/global behavior
          if applicable).

3. **HTTPProxy Inclusions / Delegation**:
    - Included `HTTPProxy` routes can reference providers defined on the root `VirtualHost` using
      `authPolicy.require`.
    - Included HTTPProxies cannot define `authorizationProviders` (since they cannot define a `VirtualHost`).

### Example YAML

```yaml
apiVersion: projectcontour.io/v1
kind: HTTPProxy
metadata:
  name: multi-auth-app
  namespace: default
spec:
  virtualhost:
    fqdn: app.example.com
    tls:
      secretName: app-tls
    authorizationProviders:
      - name: default-auth
        default: true
        extensionRef:
          name: default-authz
          namespace: auth
      - name: billing-auth
        extensionRef:
          name: billing-authz
          namespace: billing
      - name: partner-auth
        extensionRef:
          name: partner-authz
          namespace: partners
        serviceType: http
        httpSettings:
          pathPrefix: /check
  routes:
    # Uses billing-auth provider explicitly
    - conditions:
        - prefix: /billing
      authPolicy:
        require: billing-auth
        context:
          scope: billing
      services:
        - name: billing-svc
          port: 80

    # Explicitly disables authorization
    - conditions:
        - prefix: /public
      authPolicy:
        disabled: true
      services:
        - name: public-svc
          port: 80

    # Automatically uses default-auth provider
    - conditions:
        - prefix: /
      services:
        - name: app-svc
          port: 80
```

## Alternatives Considered

- **Per-route full server configuration**: Specifying the complete `ExtensionServiceReference`, `serviceType`, and
  timeout directly on each route's `authPolicy`. This was rejected because it introduces significant duplication across
  routes and diverges from the `jwtProviders` pattern.

## Security Considerations

- Misconfigured or missing provider references could lead to accidental bypass or denied traffic. Strict DAG validation
  ensures routes referencing non-existent providers fail safely (producing status condition errors rather than routing
  unauthenticated traffic).

## Compatibility

- Existing configurations using `spec.virtualhost.authorization` will continue to function.
- `spec.virtualhost.authorization` will be marked as deprecated in favor of `authorizationProviders`.
