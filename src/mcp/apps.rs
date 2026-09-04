//! Embedded MCP App resources.
//!
//! App HTML is a static shell: record data arrives only through the Apps
//! bridge as `structuredContent`. Keeping the two concrete resources here
//! gives both protocol eras one list/read implementation.

use rust_embed::RustEmbed;
use serde_json::{json, Value};

pub const MIME_TYPE: &str = "text/html;profile=mcp-app";
pub const RECORD_VERSION_DIFF_URI: &str = "ui://native-ce/record-version-diff.html";
pub const SUGGESTION_REVIEW_URI: &str = "ui://native-ce/suggestion-review.html";

#[derive(RustEmbed)]
#[folder = "web/mcp-apps/dist"]
struct AppAssets;

struct Resource {
    uri: &'static str,
    name: &'static str,
    description: &'static str,
    file: &'static str,
}

const RESOURCES: [Resource; 2] = [
    Resource {
        uri: RECORD_VERSION_DIFF_URI,
        name: "record_version_diff",
        description: "Read-only before/after record history diff",
        file: "record-version-diff.html",
    },
    Resource {
        uri: SUGGESTION_REVIEW_URI,
        name: "suggestion_review",
        description: "Stage and resolve body suggestions for one record",
        file: "suggestion-review.html",
    },
];

fn resource_ui_meta() -> Value {
    json!({
        "ui": {
            "csp": {
                "connectDomains": [],
                "resourceDomains": [],
                "frameDomains": [],
            }
        }
    })
}

pub fn list() -> Value {
    json!({
        "resources": RESOURCES.iter().map(|resource| json!({
            "uri": resource.uri,
            "name": resource.name,
            "description": resource.description,
            "mimeType": MIME_TYPE,
            "_meta": resource_ui_meta(),
        })).collect::<Vec<_>>()
    })
}

pub fn read(uri: &str) -> Option<Value> {
    let resource = RESOURCES.iter().find(|resource| resource.uri == uri)?;
    let asset = AppAssets::get(resource.file)?;
    let text = std::str::from_utf8(&asset.data).ok()?;
    Some(json!({
        "contents": [{
            "uri": resource.uri,
            "mimeType": MIME_TYPE,
            "text": text,
            "_meta": resource_ui_meta(),
        }]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_resources_are_self_contained() {
        for resource in RESOURCES {
            let result = read(resource.uri).expect("embedded App resource");
            let listed = list();
            let descriptor = listed["resources"]
                .as_array()
                .unwrap()
                .iter()
                .find(|value| value["uri"] == resource.uri)
                .unwrap();
            assert_eq!(descriptor["_meta"], result["contents"][0]["_meta"]);
            let html = result["contents"][0]["text"].as_str().unwrap();
            assert!(html.starts_with("<!doctype html>"));
            for forbidden in [
                "<script src=",
                "<link rel=\"stylesheet\"",
                "<script src=\"http",
                "<link rel=\"stylesheet\" href=\"http",
                "from \"@modelcontextprotocol",
                "from '@modelcontextprotocol",
                "fetch(",
            ] {
                assert!(
                    !html.contains(forbidden),
                    "{resource_uri}: {forbidden}",
                    resource_uri = resource.uri
                );
            }
            assert!(html.contains("ui/notifications/tool-result"));
        }
    }
}
