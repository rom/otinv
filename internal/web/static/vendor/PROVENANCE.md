# Vendored front-end assets

The GUI must work on an air-gapped laptop, so every asset is vendored here and
embedded in the binary with `embed.FS`. **No CDN references.**

| File | Version | License | SHA-256 |
|------|---------|---------|---------|
| `htmx.min.js` | htmx.org 2.0.4 | 0BSD | `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447` |
| `cytoscape.min.js` | cytoscape 3.34.3 | MIT | `5f3b5b529546d5af1fc5628590af033b74511a5b6f789f5f4682845863228b91` |

Taken from the npm tarballs, unmodified:

- `https://registry.npmjs.org/htmx.org/-/htmx.org-2.0.4.tgz`, file
  `package/dist/htmx.min.js`
- `https://registry.npmjs.org/cytoscape/-/cytoscape-3.34.3.tgz`, file
  `package/dist/cytoscape.min.js` (the UMD build, so a plain `<script>` tag
  is enough; tarball SHA-256
  `5d9e479216ed58a5f1ac639e746fd7d9770c4393f8c355dd133abc90bcc9ff3f`). Its
  MIT notice travels in the file's own header, where this build ships it.

Two things are deliberately **not** vendored:

- `cytoscape-svg`, the extension that would export the graph as SVG, is
  GPLv3. Linking it into a single binary would carry that licence into the
  whole of otinv, so the SVG export is rendered on the server instead
  (`/topology.svg`), the same way every chart in the GUI is.
- Apache ECharts: the charts are drawn as SVG on the server, which needs no
  script at all and so needs no exception in the content security policy.
  It lands here if a view arrives that genuinely needs it.
