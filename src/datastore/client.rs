use serde_json::Value;

use model::Rsvp;

#[derive(Debug)]
pub enum RsvpQueryResult {
    NotFound,
    Single(Rsvp),
    Multiple(Vec<Rsvp>),
}

impl RsvpQueryResult {
    // TODO(jacob): Figure out how to define Deserialize/Serialize for the datastore json
    //      format.
    pub fn from_json(json: &Value) -> RsvpQueryResult {
        json["batch"].get("entityResults").map_or_else(
            || RsvpQueryResult::NotFound,
            |entity_results| {
                let entities = entity_results.as_array().expect("invalid query result json");
                let rsvp_entries = entities
                    .into_iter()
                    .flat_map(|entity| Rsvp::from_json(entity))
                    .collect::<Vec<Rsvp>>();
                match rsvp_entries.as_slice() {
                    // NOTE(jacob): This should never happen, unless we get back malformed
                    //      json from google datastore. In this case we just log what we
                    //      found and look the other way.
                    [] => {
                        println!("failed to parse query result json: {}", json);
                        RsvpQueryResult::NotFound
                    },
                    [single] => RsvpQueryResult::Single(single.clone()),
                    multiple => RsvpQueryResult::Multiple(multiple.to_vec()),
                }
            },
        )
    }
}

#[derive(Debug)]
pub struct CommitResult {
    index_updates: Option<u64>,
    version: String,
}

impl CommitResult {
    pub fn from_json(json: &Value) -> Option<CommitResult> {
        let version = json
            .get("mutationResults")?
            .as_array()?
            .get(0)?
            .get("version")?
            .as_str()?
            .to_string();
        let index_updates = json.get("index_updates").map_or(
            Some(None),
            |value| value.as_u64().map(|num| Some(num)),
        )?;
        let commit_result = CommitResult {
            index_updates: index_updates,
            version: version,
        };
        Some(commit_result)
    }
}
