//! Links to the release-approved catalogue. No source is copied or consent spent.
use super::*;

pub(crate) fn packages() -> Vec<String> {
    let catalog: Vec<Value> = serde_json::from_str(include_str!(
        "../../../../web/apps/first-party-catalog.json"
    ))
    .expect("checked-in first-party catalogue");
    catalog
        .into_iter()
        .map(|entry| {
            entry["package"]
                .as_str()
                .expect("catalogue package")
                .to_owned()
        })
        .collect()
}

pub(crate) fn prepare(package: &str, public_origin: Option<&str>) -> Result<Value> {
    let catalog: Vec<Value> = serde_json::from_str(include_str!(
        "../../../../web/apps/first-party-catalog.json"
    ))?;
    catalog
        .iter()
        .find(|entry| entry["package"] == package)
        .ok_or_else(|| {
            Error::engine("manage_alpha_tabs: package is not in the approved catalogue")
        })?;
    // Approved package identities contain only URL-query-safe ASCII.
    if !package
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
    {
        return Err(Error::engine(
            "manage_alpha_tabs: invalid catalogue package",
        ));
    }
    let path = format!("/shell/?install={package}");
    Ok(json!({"package":package,
        "install_path":path,"install_url":public_origin.map(|origin|format!("{}{path}",origin.trim_end_matches('/'))),
        "installation_changed":false,"requires_person_consent":true,
        "next_step":"Open this link in a browser, sign in if needed, and choose Add on the app's access screen. No app bytes need to pass through the agent."}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_use_the_release_allowlist_and_the_configured_public_origin() {
        for package in packages() {
            let link = prepare(&package, Some("https://native.example")).unwrap();
            assert_eq!(
                link["install_url"],
                format!("https://native.example/shell/?install={package}")
            );
            assert_eq!(link["requires_person_consent"], true);
            assert_eq!(link["installation_changed"], false);
            assert!(link.get("body").is_none());
            assert!(link.get("version").is_none());
        }
        assert!(prepare("https://other.example/app", Some("https://native.example")).is_err());
        assert!(prepare("agent.unknown", None).is_err());
        assert!(prepare("agent.docs", None).unwrap()["install_url"].is_null());
    }
}
