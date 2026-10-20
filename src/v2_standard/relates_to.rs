//! Current storage-free service; recorded execution belongs to the catalogue.
pub use super::relates_to_v3::*;

pub(crate) fn interpreter(
    pins: &crate::kernel::InterpretationPins,
) -> crate::error::Result<&'static crate::kernel::provider_catalogue::Entry> {
    crate::kernel::provider_catalogue::lookup(pins)
}
pub fn retained_package(
    pins: &crate::kernel::InterpretationPins,
) -> crate::error::Result<crate::package_manifest::PackageManifest> {
    Ok((interpreter(pins)?.package)())
}
pub fn known_package(package: &crate::package_manifest::PackageManifest) -> bool {
    // Computing pins validates package identity and would recurse through this
    // exact-package admission check. Compare manifest identity fields directly.
    package.namespace == NAMESPACE
        && package.name == PACKAGE
        && crate::kernel::provider_catalogue::entries()
            .iter()
            .any(|e| (e.package)() == *package)
}

pub(crate) use super::relates_to_retained as retained;
