use jsonwebtoken::{self, Algorithm, Validation};
use serde_json::Value;

use AccountData;
use service::form::FormValue;

// TODO(jacob): Use Value::pointer instead of indexing for all of these.
fn parse_array_value<T>(
    json: &Value,
    value_reader: &Fn(&Value) -> Option<T>
) -> Option<Vec<T>> {
    json["arrayValue"]["values"].as_array().map(|values| {
        values.into_iter().flat_map(value_reader).collect()
    })
}

fn parse_boolean_value(json: &Value) -> Option<bool> {
    json["booleanValue"].as_bool()
}

fn parse_integer_value(json: &Value) -> Option<u8> {
    // GCP datastore handles integers encoded as strings.
    json["integerValue"].as_str().and_then(|s| s.parse().ok())
}

fn parse_string_value(json: &Value) -> Option<String> {
    json["stringValue"].as_str().map(|s| s.to_string())
}

fn render_array_value<T>(values: &Vec<T>, render_value: &Fn(&T) -> Value) -> Value {
    json!({
        "arrayValue": {
            "values": Value::Array(values.into_iter().map(render_value).collect()),
        },
    })
}

fn render_boolean_value(value: &bool, exclude_from_indexes: bool) -> Value {
    json!({
        "booleanValue": value,
        "excludeFromIndexes": exclude_from_indexes,
    })
}

// GCP datastore handles integers encoded as strings.
fn render_integer_value(value: &String, exclude_from_indexes: bool) -> Value {
    json!({
        "integerValue": value,
        "excludeFromIndexes": exclude_from_indexes,
    })
}

fn render_string_value(value: &String, exclude_from_indexes: bool) -> Value {
    json!({
        "stringValue": value,
        "excludeFromIndexes": exclude_from_indexes,
    })
}

#[derive(Clone, Debug)]
pub struct Name {
    pub first_name: String,
    pub last_name: String,
}

impl Name {
    // TODO(jacob): Figure out how to define Deserialize/Serialize for the datastore json
    //      format.
    fn from_json(json: &Value) -> Option<Name> {
        let properties = &json["entityValue"]["properties"];
        let first_name = parse_string_value(&properties["first_name"])?;
        let last_name = parse_string_value(&properties["last_name"])?;
        let name = Name {
            first_name: first_name,
            last_name: last_name,
        };
        Some(name)
    }

    fn to_json(&self, exclude_from_indexes: bool) -> Value {
        json!({
            "entityValue": {
                "properties": {
                  "first_name": render_string_value(&self.first_name, exclude_from_indexes),
                  "last_name": render_string_value(&self.last_name, exclude_from_indexes),
                },
            },
        })
    }
}

#[derive(Clone, Debug)]
pub struct Guest {
    pub name: Name,
    pub dietary_notes: String,
}

impl Guest {
    // TODO(jacob): Figure out how to define Deserialize/Serialize for the datastore json
    //      format.
    fn from_json(json: &Value) -> Option<Guest> {
        let properties = &json["entityValue"]["properties"];
        let name = Name::from_json(&properties["name"])?;
        let dietary_notes = parse_string_value(&properties["dietary_notes"])?;
        let guest = Guest {
            name: name,
            dietary_notes: dietary_notes,
        };
        Some(guest)
    }

    fn to_json(&self) -> Value {
        json!({
            "entityValue": {
                "properties": {
                    "name": self.name.to_json(true),
                    "dietary_notes": render_string_value(&self.dietary_notes, true),
                },
            },
        })
    }
}

// TODO(jacob): Is there some way to de-dupe common fields here?
#[derive(Clone, Debug)]
pub enum Rsvp {
    /* A database entry for someone who has not yet RSVPed */
    Empty {
        key: Value,
        invited: Vec<Name>,
        invited_count: u8,
    },
    /* A database entry for someone who has RSVPed */
    Full {
        key: Value,
        attending: Vec<Guest>,
        email: String,
        going: bool,
        invited: Vec<Name>,
        other_notes: String,
        invited_count: u8,
    },
}

impl Rsvp {
    pub fn from_form_data(
        account_data: &AccountData,
        form_data: &[u8]
    ) -> Option<Rsvp> {
        let params = FormValue::parse_form_data(form_data);

        let token = params.get("token")?.as_string()?;
        let token_data = jsonwebtoken::decode::<Value>(
            &token,
            &account_data.public_key,
            &Validation::new(Algorithm::RS256),
        ).ok()?.claims;

        let key = token_data.get("key")?.clone();
        let invited = parse_array_value(&token_data["invited"], &Name::from_json)?;
        let invited_count = parse_integer_value(&token_data["invited_count"])?;

        let first_names = params.get("first_name")?.as_array()?;
        let last_names = params.get("last_name")?.as_array()?;
        let dietary_noteses = params.get("dietary_notes")?.as_array()?;
        let attending = first_names.into_iter().zip(last_names).zip(dietary_noteses)
            .map(|((first_name, last_name), dietary_notes)| {
                Guest {
                    name: Name {
                        first_name: first_name,
                        last_name: last_name,
                    },
                    dietary_notes: dietary_notes,
                }
            }).collect();

        let email = params.get("email")?.as_string()?;
        let going = params.get("going")
            .map_or(Some(false), |going_param| Some(going_param.as_string()? == "yes"))?;
        let other_notes = params.get("other_notes")?.as_string()?;

        let full_rsvp = Rsvp::Full {
            key: key,
            attending: attending,
            email: email,
            invited: invited,
            going: going,
            other_notes: other_notes,
            invited_count: invited_count,
        };
        Some(full_rsvp)
    }

    // TODO(jacob): Figure out how to define Deserialize/Serialize for the datastore json
    //      format.
    pub fn from_json(json: &Value) -> Option<Rsvp> {
        let key = json["entity"]["key"].clone();
        let properties = &json["entity"]["properties"];
        let invited = parse_array_value(&properties["invited"], &Name::from_json)?;
        let invited_count = parse_integer_value(&properties["invited_count"])?;

        match parse_boolean_value(&properties["going"]) {
            None => {
                let empty_rsvp = Rsvp::Empty {
                    key: key,
                    invited: invited,
                    invited_count: invited_count,
                };
                Some(empty_rsvp)
            },

            Some(going) => {
                let attending = parse_array_value(&properties["attending"], &Guest::from_json)?;
                let email = parse_string_value(&properties["email"])?;
                let other_notes = parse_string_value(&properties["other_notes"])?;

                let full_rsvp = Rsvp::Full {
                    key: key,
                    attending: attending,
                    email: email,
                    going: going,
                    invited: invited,
                    other_notes: other_notes,
                    invited_count: invited_count,
                };
                Some(full_rsvp)
            },
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Rsvp::Empty {
                key,
                invited,
                invited_count,
            } => json!({
                "key": key,
                "invited": render_array_value(&invited, &|name| name.to_json(false)),
                "invited_count": render_integer_value(&invited_count.to_string(), true),
            }),

            Rsvp::Full {
                key,
                attending,
                email,
                going,
                invited,
                other_notes,
                invited_count,
            } => json!({
                "key": key,
                "properties": {
                    "attending": render_array_value(&attending, &|guest| guest.to_json()),
                    "email": render_string_value(&email, true),
                    "invited": render_array_value(&invited, &|name| name.to_json(false)),
                    "going": render_boolean_value(&going, false),
                    "other_notes": render_string_value(&other_notes, true),
                    "invited_count": render_integer_value(&invited_count.to_string(), true),
                },
            }),
        }
    }
}
