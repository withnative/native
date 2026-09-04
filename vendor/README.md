# Vendored compatibility patches

`swc_common-12.0.1` is the crate selected by the exact `mdxjs 1.0.4` runtime
pin. Its source imports serde's old unversioned private facade, removed by the
serde version required by native-ce's current JWT dependency. The vendored
copy is the published crate with one compatibility-only path change:
`serde::__private` → `serde::__private228`.

This directory must be revisited with any MDX compiler or serde upgrade. Those
upgrades also require a `native.mdx.v1` adapter-revision/cache-namespace review.
