# amber-resolver

Resolves manifest references into parsed `Manifest` values plus source text and span metadata. This is the IO boundary for the compiler.

## Responsibilities
- Load manifests from `file://` and `http(s)://` URLs.
- Verify optional digest pins during resolution.
- Expose custom resolvers for additional URL schemes.

## Key types
- `Resolver`: dispatches by URL scheme and performs digest checks.
- `Resolution`: parsed manifest + source + spans.
- `RemoteResolver` / `Backend`: plug-in interface for custom schemes.

## Design notes
- Remote resolver dispatch prefers the most recently added resolver for a scheme.
- HTTP resolution enforces size limits and optional content-type policy.
