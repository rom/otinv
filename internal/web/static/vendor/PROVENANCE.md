# Vendored front-end assets

The GUI must work on an air-gapped laptop, so every asset is vendored here and
embedded in the binary with `embed.FS`. **No CDN references.**

| File | Version | License | SHA-256 |
|------|---------|---------|---------|
| `htmx.min.js` | htmx.org 2.0.4 | 0BSD | `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447` |

Taken from the npm tarball `https://registry.npmjs.org/htmx.org/-/htmx.org-2.0.4.tgz`,
file `package/dist/htmx.min.js`.

Cytoscape.js and Apache ECharts land here with the topology and chart views.
