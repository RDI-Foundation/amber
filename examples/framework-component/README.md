<!--
amber-docs
summary: Create and destroy dynamic children through the supported `framework.component` capability.
-->
# `framework.component` Example

This example shows the supported Amber path for dynamic component creation.

The root manifest gives `admin` a `framework.component` binding. That capability is a realm
authority: `admin` can inspect child templates, create children under the root realm, destroy them
again, and snapshot the live graph.

Files:

- `scenario.json5`: root manifest with one `admin` component and one `worker` child template.
- `admin.json5`: direct-runtime component that talks to its `framework.component` slot over HTTP.
- `worker.json5`: direct-runtime child template that exports a tiny HTTP endpoint.
- `admin.py`: helper app with `/children`, `/create/<name>`, `/destroy/<name>`, and `/snapshot`.
- `worker.py`: tiny HTTP server used by dynamically created children.

Run it:

```sh
cd examples/framework-component
amber run .
```

Amber prints the exported `admin_http` URL. In another terminal:

```sh
curl http://127.0.0.1:18080/children
curl http://127.0.0.1:18080/create/job-1
curl http://127.0.0.1:18080/children
curl http://127.0.0.1:18080/snapshot
curl http://127.0.0.1:18080/destroy/job-1
```

Notes:

- This example keeps everything on the direct runtime so the control flow is easy to inspect.
- `framework.component` is the supported public interface for dynamic children.
- Backend-specific experimental control capabilities may still exist for niche cases, but they are
  not the recommended authoring surface for dynamic components.
