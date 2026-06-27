# Konfig - Policy Configuration Context

## Overview

Konfig is a policy evaluation library for reverse proxy configurations. It provides a flexible, composable policy system for controlling access to resources based on HTTP method, path, and JWT token claims.

## Core Concepts

### Organization
An organization represents a tenant in the system. Each organization has:
- **id**: Unique identifier
- **name**: Human-readable name
- **domains**: List of domains this organization owns
- **policies**: General policies applied to all domains
- **domain_policies**: Per-domain policies (keyed by domain name)
- **upstream**: Backend server configuration
- **auth**: Authentication configuration

### Policy
A policy defines access rules with:
- **id**: Unique identifier
- **name**: Human-readable name
- **effect**: `Allow` or `Deny`
- **rules**: List of policy rules (any match triggers the effect)

### PolicyRule
Each rule specifies:
- **resource**: Path pattern to match (`Exact`, `Prefix`, or `Glob`)
- **methods**: HTTP methods to match (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`)
- **conditions**: Optional claim-based conditions

### Conditions
Conditions evaluate JWT token claims:
- **claim**: Claim field to check (`sub`, `org_id`, or custom)
- **operator**: Comparison operator (`Equals`, `NotEquals`, `Contains`, `StartsWith`, `In`, `NotIn`)
- **value**: Expected value (comma-separated for `In`/`NotIn`)

## Policy Evaluation Logic

1. **Domain policies** are checked first if they exist for the request's domain
2. **General policies** are checked if no domain policies exist
3. **Deny** effect: If any Deny policy matches, access is denied immediately
4. **Allow** effect: Access is granted only if at least one Allow policy matches
5. **No policies**: If no policies exist, all access is allowed

### Priority Rules
- Domain-specific policies override general policies
- Deny always takes precedence over Allow
- If domain policies exist but none match, access is denied (even if general policies would allow)

## Resource Patterns

| Pattern | Syntax | Example | Matches |
|---------|--------|---------|---------|
| Exact | Exact("/api/v1/users") | `/api/v1/users` | Only exact path |
| Prefix | Prefix("/api/v1/") | `/api/v1/users`, `/api/v1/posts` | Any path starting with prefix |
| Glob | Glob("/api/*/users/*") | `/api/v1/users/123` | Wildcard matching (`*` = any, `?` = single char) |

## Example Configurations

### Basic Allow Policy
```json
{
  "id": "allow-read",
  "name": "Allow reading resources",
  "effect": "Allow",
  "rules": [{
    "resource": {"Prefix": "/api/public/"},
    "methods": ["GET"],
    "conditions": []
  }]
}
```

### Deny Policy
```json
{
  "id": "deny-admin",
  "name": "Deny admin endpoints",
  "effect": "Deny",
  "rules": [{
    "resource": {"Prefix": "/api/admin/"},
    "methods": ["GET", "POST", "DELETE"],
    "conditions": []
  }]
}
```

### Condition-Based Policy
```json
{
  "id": "allow-admins",
  "name": "Allow admin users only",
  "effect": "Allow",
  "rules": [{
    "resource": {"Prefix": "/api/"},
    "methods": ["GET", "POST"],
    "conditions": [
      {
        "claim": "sub",
        "operator": "StartsWith",
        "value": "admin-"
      }
    ]
  }]
}
```

### Domain-Specific Policy
```json
{
  "id": "internal-admin",
  "name": "Allow admin on internal domain",
  "effect": "Allow",
  "rules": [{
    "resource": {"Prefix": "/api/admin/"},
    "methods": ["GET", "POST"],
    "conditions": [
      {
        "claim": "org_id",
        "operator": "Equals",
        "value": "org1"
      }
    ]
  }]
}
```

## Complete Organization Config

```json
{
  "id": "org1",
  "name": "Acme Corp",
  "domains": ["app.acme.com", "api.acme.com"],
  "policies": [
    {
      "id": "general-read",
      "name": "Allow reading public resources",
      "effect": "Allow",
      "rules": [{
        "resource": {"Prefix": "/api/public/"},
        "methods": ["GET"],
        "conditions": []
      }]
    }
  ],
  "domain_policies": {
    "api.acme.com": [
      {
        "id": "api-deny-delete",
        "name": "Deny delete on API",
        "effect": "Deny",
        "rules": [{
          "resource": {"Prefix": "/api/"},
          "methods": ["DELETE"],
          "conditions": []
        }]
      }
    ],
    "internal.acme.com": [
      {
        "id": "internal-allow-admin",
        "name": "Allow admin on internal",
        "effect": "Allow",
        "rules": [{
          "resource": {"Prefix": "/api/admin/"},
          "methods": ["GET", "POST"],
          "conditions": [
            {"claim": "org_id", "operator": "Equals", "value": "org1"}
          ]
        }]
      }
    ]
  },
  "upstream": {
    "base_url": "https://backend.acme.com",
    "timeout_ms": 10000,
    "max_retries": 5
  },
  "auth": {
    "jwt_issuer": "https://auth.acme.com",
    "jwt_audience": "acme-proxy",
    "jwks_url": "https://auth.acme.com/.well-known/jwks.json",
    "token_header": "Authorization",
    "token_prefix": "Bearer",
    "redirect_url": "https://auth.acme.com/sso"
  }
}
```

## Building a Policy Config Generator

### Required Inputs
1. Organization details (id, name, domains)
2. Upstream configuration (base_url, timeout, retries)
3. Auth configuration (issuer, audience, JWKS URL, token settings)
4. Policy definitions (rules, effects, conditions)

### UI Components Needed
1. **Organization Form**: Basic org info, domain management
2. **Policy Builder**: 
   - Resource pattern selector (Exact/Prefix/Glob)
   - Method selector (checkboxes for HTTP methods)
   - Condition builder (claim, operator, value)
   - Effect toggle (Allow/Deny)
3. **Policy List**: Drag-and-drop ordering, enable/disable, delete
4. **Preview**: JSON output with validation
5. **Import/Export**: Load/save configurations

### Validation Rules
- Policy IDs must be unique within an organization
- Resource patterns must start with `/`
- Conditions must reference valid claims (`sub`, `org_id`, or custom)
- `In`/`NotIn` operators require comma-separated values
- Domains must be valid hostnames
- Upstream URLs must be valid HTTP(S) URLs

### Common Patterns to Support
1. **Read-Only Access**: Allow GET/HEAD on specific paths
2. **Admin Access**: Allow all methods but restrict by claim
3. **Rate Limiting by Role**: Different policies for different user roles
4. **Domain Isolation**: Separate policies per domain
5. **Blacklist Pattern**: Deny specific paths/methods, allow everything else
6. **Whitelist Pattern**: Allow specific paths/methods, deny everything else
