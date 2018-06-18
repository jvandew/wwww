extern crate bytes;
extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate itertools;
extern crate jsonwebtoken as jwt;
extern crate regex;
extern crate tokio_core;
extern crate url;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;

use bytes::Bytes;
use futures::Future;
use futures::future;
use futures::stream::Stream;
use hyper::{Body, Client, Method, StatusCode, Uri};
use hyper::{Error as HyperError};
use hyper::client::{self, HttpConnector};
use hyper::header::{self, Accept, Authorization, Bearer, ContentType};
use hyper::mime::APPLICATION_JSON;
use hyper::server::{self, Http, Service};
use hyper_tls::HttpsConnector;
use jwt::{Algorithm, Header, Validation};
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Read;
use std::iter::FromIterator;
use std::fs::{self, File};
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_core::reactor::Core;
use url::form_urlencoded;

static DATASTORE_API: &'static str = "google.datastore.v1.Datastore";
static DATASTORE_HOST: &'static str = "https://datastore.googleapis.com";

type ResponseFuture = Box<Future<Item = server::Response<Body>, Error = HyperError>>;

// TODO(jacob): convert all Strings to &str
#[derive(Deserialize, Serialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
}

#[derive(Clone, Deserialize, Serialize)]
struct AccountDetails {
    project_id: String,
    private_key_id: String,
    client_email: String,
}

#[derive(Clone)]
struct AccountData {
    details: AccountDetails,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
struct RsvpCredentials {
    admin: String,
    user: String,
}

#[derive(Debug)]
struct LoginData {
    first_name: String,
    last_name: String,
    password: String,
}

impl LoginData {
    fn from_form_data(form_data: &[u8]) -> Option<LoginData> {
        let params = form_urlencoded::parse(form_data).collect::<HashMap<_, _>>();
        let first_name = params.get("first_name")?;
        let last_name = params.get("last_name")?;
        let password = params.get("password")?;

        let login_data = LoginData {
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
            password: password.to_string(),
        };
        Some(login_data)
    }
}

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
struct Name {
    first_name: String,
    last_name: String,
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
struct Guest {
    name: Name,
    dietary_notes: String,
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
enum Rsvp {
    /* A database entry for someone who has not yet RSVPed */
    Empty {
        key: Value,
        invited: Vec<Name>,
        plus_ones: u8,
    },
    /* A database entry for someone who has RSVPed */
    Full {
        key: Value,
        attending: Vec<Guest>,
        email: String,
        going: bool,
        invited: Vec<Name>,
        other_notes: String,
        plus_ones: u8,
    },
}

impl Rsvp {
    fn from_form_data(
        account_data: &AccountData,
        form_data: &[u8]
    ) -> Option<Rsvp> {
        let params = FormValue::parse_form_data(form_data);

        let token = params.get("token")?.as_string()?;
        let token_data = jwt::decode::<Value>(
            &token,
            &account_data.public_key,
            &Validation::new(Algorithm::RS256),
        ).ok()?.claims;

        let key = token_data.get("key")?.clone();
        let invited = parse_array_value(&token_data["invited"], &Name::from_json)?;
        let plus_ones = parse_integer_value(&token_data["plus_ones"])?;

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
            plus_ones: plus_ones,
        };
        Some(full_rsvp)
    }

    // TODO(jacob): Figure out how to define Deserialize/Serialize for the datastore json
    //      format.
    fn from_json(json: &Value) -> Option<Rsvp> {
        let key = json["entity"]["key"].clone();
        let properties = &json["entity"]["properties"];
        let invited = parse_array_value(&properties["invited"], &Name::from_json)?;
        let plus_ones = parse_integer_value(&properties["plus_ones"])?;

        match parse_boolean_value(&properties["going"]) {
            None => {
                let empty_rsvp = Rsvp::Empty {
                    key: key,
                    invited: invited,
                    plus_ones: plus_ones,
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
                    plus_ones: plus_ones,
                };
                Some(full_rsvp)
            },
        }
    }

    fn to_json(&self) -> Value {
        match self {
            Rsvp::Empty {
                key,
                invited,
                plus_ones,
            } => json!({
                "key": key,
                "invited": render_array_value(&invited, &|name| name.to_json(false)),
                "plus_ones": render_integer_value(&plus_ones.to_string(), true),
            }),

            Rsvp::Full {
                key,
                attending,
                email,
                going,
                invited,
                other_notes,
                plus_ones,
            } => json!({
                "key": key,
                "properties": {
                    "attending": render_array_value(&attending, &|guest| guest.to_json()),
                    "email": render_string_value(&email, true),
                    "invited": render_array_value(&invited, &|name| name.to_json(false)),
                    "going": render_boolean_value(&going, false),
                    "other_notes": render_string_value(&other_notes, true),
                    "plus_ones": render_integer_value(&plus_ones.to_string(), true),
                },
            }),
        }
    }
}

#[derive(Debug)]
enum RsvpQueryResult {
    NotFound,
    Single(Rsvp),
    Multiple(Vec<Rsvp>),
}

impl RsvpQueryResult {
    // TODO(jacob): Figure out how to define Deserialize/Serialize for the datastore json
    //      format.
    fn from_json(json: &Value) -> RsvpQueryResult {
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
enum FormValue {
    String(String),
    Array(Vec<String>),
}

impl FormValue {
    fn as_array(&self) -> Option<Vec<String>> {
        match self {
            FormValue::String(_) => None,
            FormValue::Array(array) => Some(array.to_vec()),
        }
    }

    fn as_string(&self) -> Option<String> {
        match self {
            FormValue::String(string) => Some(string.to_string()),
            FormValue::Array(_) => None,
        }
    }

    /* form_urlencoded::parse does not handle array data correctly, so we define our own
     * helper here.
     *
     * NOTE(jacob): This function takes some liberties with data validation -- in
     *      particular, undefined behavior includes:
     *          - mixed array and non-array values for a single variable
     *          - multiple occurances of the same variable
     *          - skipping array indices
     */
    fn parse_form_data(form_data: &[u8]) -> HashMap<String, FormValue> {
        // Parse everything into vectors for simplicity, and then do a final pass to convert
        // to the appropriate enum.
        let initial_vector_map: HashMap<String, Vec<Option<String>>> = HashMap::new();
        // TODO(jacob): figure out how to cache this
        let array_regex = Regex::new(r"(?P<name>.+)\[(?P<index>\d+)\]").unwrap();

        let vector_map = form_urlencoded::parse(form_data)
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .fold(
                initial_vector_map,
                |mut vector_map, (name, value)| {
                    let (var_name, index, mut new_vector) = array_regex.captures(&name)
                        .and_then(|captures| {
                            captures.name("name")
                                .map(|mat| mat.as_str())
                                .and_then(|var_name| {
                                    captures.name("index").map(|mat| (var_name, mat.as_str()))
                                }).and_then(|(var_name, index_str)| {
                                    str::parse::<usize>(index_str).ok()
                                        .map(|index| (var_name.to_string(), index))
                                })
                        }).map_or_else(
                            || {
                                let mut new_values = Vec::with_capacity(1);
                                new_values.resize(1, None);
                                (name, 0, new_values)
                            },
                            |(var_name, index)| {
                                let new_vector = vector_map.get(&var_name).map_or_else(
                                    || {
                                        let mut new_values = Vec::with_capacity(index + 1);
                                        new_values.resize(index + 1, None);
                                        new_values
                                    },
                                    |values| {
                                        let mut new_values = values.clone();
                                        if new_values.len() <= index {
                                            new_values.resize(index + 1, None);
                                        };
                                        new_values
                                    },
                                );
                                (var_name, index, new_vector)
                            },
                        );

                    new_vector[index] = Some(value);
                    vector_map.insert(var_name, new_vector);
                    vector_map
                }
            );

        vector_map.into_iter().flat_map(|(name, values)| {
            let flattened_values = values.into_iter().flat_map(|value_opt| value_opt).collect::<Vec<String>>();
            match &flattened_values[..] {
                [] => None,  // should never happen with well-formed input
                [single] => Some((name, FormValue::String(single.to_string()))),
                many => Some((name, FormValue::Array(many.to_vec()))),
            }
        }).collect()
    }
}

#[derive(Clone)]
struct RsvpService {
    datastore_client: Client<HttpsConnector<HttpConnector>, Body>,
    account_data: AccountData,
    rsvp_credentials: RsvpCredentials,
}

impl RsvpService {
    fn new(
        datastore_client: Client<HttpsConnector<HttpConnector>, Body>,
        account_data: AccountData,
        rsvp_credentials: RsvpCredentials,
    ) -> RsvpService {
        RsvpService {
            datastore_client: datastore_client,
            account_data: account_data,
            rsvp_credentials: rsvp_credentials,
        }
    }

    fn get_datastore_token(account_data: &AccountData) -> String {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Error getting unix timestamp")
            .as_secs();

        let mut jwt_header = Header::default();
        jwt_header.alg = Algorithm::RS256;
        jwt_header.kid = Some(account_data.details.private_key_id.clone());
        jwt_header.typ = Some("JWT".to_string());

        let claims = Claims {
            iss: account_data.details.client_email.clone(),
            sub: account_data.details.client_email.clone(),
            aud: format!("{}/{}", DATASTORE_HOST, DATASTORE_API),
            iat: time,
            exp: time + 3600,
        };

        jwt::encode(&jwt_header, &claims, &account_data.private_key)
            .expect("Error encoding json web token")
    }

    fn build_datastore_request(
        account_data: &AccountData,
        endpoint: &str,
        request_json: String,
    ) -> client::Request<Body> {
        let uri = format!(
            "{}/v1/projects/{}:{}",
            DATASTORE_HOST,
            account_data.details.project_id,
            endpoint,
        ).parse().expect("Unable to parse query uri");

        let token = RsvpService::get_datastore_token(account_data);

        let mut request = client::Request::new(Method::Post, uri);
        request.headers_mut().set(Accept(vec![header::qitem(APPLICATION_JSON)]));
        request.headers_mut().set(Authorization(Bearer { token: token }));
        request.headers_mut().set(ContentType(APPLICATION_JSON));
        request.set_body(Body::from(request_json));
        request
    }

    fn build_commit_request(
        account_data: &AccountData,
        transaction_id: &str,
        rsvp: Rsvp,
    ) -> client::Request<Body> {
        let commit_request = json!({
            "mode": "TRANSACTIONAL",
            "mutations": [
                {
                    "update": rsvp.to_json(),
                },
            ],
            "transaction": transaction_id,
        }).to_string();
        RsvpService::build_datastore_request(
            account_data,
            "commit",
            commit_request,
        )
    }

    fn build_query_request(
        account_data: &AccountData,
        first_name: &str,
        last_name: &str,
    ) -> client::Request<Body> {
        let query_request = json!({
            "query": {
                "filter": {
                    "compositeFilter": {
                        "op": "AND",
                        "filters": [
                            {
                                "propertyFilter": {
                                    "property": {
                                        "name": "invited.first_name",
                                    },
                                    "op": "EQUAL",
                                    "value": {
                                        "stringValue": first_name.to_lowercase(),
                                    },
                                },
                            },
                            {
                                "propertyFilter": {
                                    "property": {
                                        "name": "invited.last_name",
                                    },
                                    "op": "EQUAL",
                                    "value": {
                                        "stringValue": last_name.to_lowercase(),
                                    },
                                },
                            },
                        ],
                    },
                },
                "kind": [
                    {
                        "name": "rsvp",
                    },
                ],
            },
        }).to_string();
        RsvpService::build_datastore_request(account_data, "runQuery", query_request)
    }

    fn build_transaction_request(account_data: &AccountData) -> client::Request<Body> {
        let transaction_request = json!({
            "transactionOptions": {
                "readWrite": {
                }
            }
        }).to_string();
        RsvpService::build_datastore_request(
            account_data,
            "beginTransaction",
            transaction_request,
        )
    }

    fn failed_login(status_code: StatusCode, reason: String) -> ResponseFuture {
        let file = File::open(format!("www/rsvp.html"))
            .expect("failed to open login form file");
        let mut buf_reader = BufReader::new(file);
        let mut template = String::new();
        buf_reader.read_to_string(&mut template)
            .expect("failed to read login form file");
        let rendered = template.replace("<!--$login_error-->", &reason);
        let response = server::Response::new()
            .with_status(status_code)
            .with_body(Body::from(rendered));
        Box::new(future::ok(response))
    }

    // TODO(jacob): This should be a method on self.
    fn handle_login(
        account_data: AccountData,
        datastore_client: Client<HttpsConnector<HttpConnector>, Body>,
        rsvp_credentials: RsvpCredentials,
        data: &[u8],
    ) -> Option<ResponseFuture> {
        let login_data = LoginData::from_form_data(data)?;
        println!("login attempt: {:?}", login_data);

        if login_data.password != rsvp_credentials.user {
            let response_future = RsvpService::failed_login(
                StatusCode::Unauthorized,
                "Invalid login, please try again.".to_string(),
            );
            Some(response_future)

        } else {
            let request = RsvpService::build_query_request(
                &account_data,
                &login_data.first_name,
                &login_data.last_name,
            );

            let response_future = datastore_client.request(request).and_then(move |response| {
                response.body().concat2().and_then(move |raw_query_result| {
                    let query_result_string = str::from_utf8(&raw_query_result)
                        .expect("unable to parse database rsvp entry");
                    let query_result_json = serde_json::from_str(query_result_string)
                        .expect("unable to parse database rsvp json");

                    match RsvpQueryResult::from_json(&query_result_json) {
                        RsvpQueryResult::NotFound => RsvpService::failed_login(
                            StatusCode::NotFound,
                            "Guest not found, please try again.".to_string(),
                        ),

                        RsvpQueryResult::Multiple(rsvps) => {
                            println!(
                                "multiple rsvp entries found for {}, {}: {:?}",
                                login_data.last_name,
                                login_data.first_name,
                                rsvps,
                            );
                            RsvpService::failed_login(
                                StatusCode::InternalServerError,
                                "Multiple guest entries found, please contact Jacob.".to_string(),
                            )
                        },

                        RsvpQueryResult::Single(rsvp) => {
                            RsvpService::render_form(&account_data, rsvp)
                        },
                    }
                })
            });
            Some(Box::new(response_future))
        }
    }

    fn handle_static(uri: Uri) -> ResponseFuture {
        let response = File::open(format!("www{}", uri)).ok().map_or_else(
            || server::Response::new()
                .with_status(StatusCode::NotFound)
                .with_body("Not Found"),
            |file| {
                let bytes = Bytes::from_iter(itertools::flatten(file.bytes()));
                server::Response::new()
                    .with_body(Body::from(bytes))
            },
        );
        Box::new(future::ok(response))
    }

    // TODO(jacob): This should be a method on self.
    fn handle_submission<'a>(
        account_data: AccountData,
        datastore_client: Client<HttpsConnector<HttpConnector>, Body>,
        data: &[u8],
    ) -> Option<ResponseFuture> {
        let rsvp = Rsvp::from_form_data(&account_data, data)?.clone();
        let transaction_request = RsvpService::build_transaction_request(&account_data);

        let response_future = datastore_client.request(transaction_request)
            .and_then(move |transaction_response| {
                transaction_response.body().concat2().and_then(move |raw_result| {
                    let transaction_string = str::from_utf8(&raw_result)
                        .expect("unable to parse transaction response");
                    let transaction_json = serde_json::from_str::<Value>(transaction_string)
                        .expect("unable to parse transaction json");

                    transaction_json["transaction"].as_str().map_or_else(
                        || RsvpService::failed_login(
                            StatusCode::InternalServerError,
                            "Database query failure, please contact Jacob.".to_string(),
                        ),

                        |transaction_id| {
                            let commit_request = RsvpService::build_commit_request(
                                &account_data,
                                transaction_id,
                                rsvp,
                            );
                            let response_future = datastore_client.request(commit_request)
                                .and_then(|commit_response| {
                                    commit_response.body().concat2().map(|raw_commit_result| {
                                        let commit_string = str::from_utf8(&raw_commit_result)
                                            .expect("unable to parse commit response");

                                        server::Response::new()
                                            .with_body(Body::from(commit_string.to_string()))
                                    })
                                });
                            Box::new(response_future)
                        }
                    )
                })
            });
        Some(Box::new(response_future))
    }

    fn get_auth_token(
        account_data: &AccountData,
        rsvp: &Rsvp,
    ) -> String {
        let empty_rsvp_json = match rsvp {
            empty @ Rsvp::Empty { .. } => empty.to_json(),
            Rsvp::Full {
                key,
                attending: _,
                email: _,
                going: _,
                invited,
                other_notes: _,
                plus_ones,
            } => {
                let empty = Rsvp::Empty {
                    key: key.clone(),
                    invited: invited.to_vec(),
                    plus_ones: *plus_ones,
                };
                empty.to_json()
            }
        };

        let mut header = Header::default();
        header.alg = Algorithm::RS256;
        jwt::encode(&header, &empty_rsvp_json, &account_data.private_key)
            .expect("Error encoding auth token")
    }

    fn render_form(account_data: &AccountData, rsvp: Rsvp) -> ResponseFuture {
        let form_file = File::open("www/rsvp2.html").expect("failed to open rsvp form template");
        let mut form_reader = BufReader::new(form_file);
        let mut form_template = String::new();
        form_reader.read_to_string(&mut form_template).expect("failed to read form template");

        let guest_file = File::open("templates/guest.html").expect("failed to open guest template");
        let mut guest_reader = BufReader::new(guest_file);
        let mut guest_template = String::new();
        guest_reader.read_to_string(&mut guest_template).expect("failed to read guest template");

        let token = RsvpService::get_auth_token(account_data, &rsvp);
        let rendered = match rsvp {
            Rsvp::Empty {
                key: _,
                invited,
                plus_ones,
            } => {
                let guests = (0..(invited.len() + plus_ones as usize)).fold(
                    String::new(),
                    |mut guests_builder, guest_num| {
                        let rendered_guest = guest_template
                            .replace("$num", &(guest_num + 1).to_string())
                            .replace("$index", &guest_num.to_string())
                            .replace("$first_name", "")
                            .replace("$last_name", "")
                            .replace("$dietary_notes", "");
                        guests_builder.push_str(&rendered_guest);
                        guests_builder
                    },
                );

                form_template
                    .replace("$token", &token)
                    .replace("$checked", "checked")
                    .replace("$guests", &guests)
                    .replace("$email", "")
                    .replace("$other_notes", "")
            },

            Rsvp::Full {
                key: _,
                attending,
                email,
                going,
                invited,
                other_notes,
                plus_ones,
            } => {
                let checked = if going { "checked" } else { "" };
                let guests = (0..(invited.len() + plus_ones as usize)).fold(
                    String::new(),
                    |mut guests_builder, guest_num| {
                        let attending_opt = attending.get(guest_num);
                        let first_name = attending_opt
                            .map(|a| a.name.first_name.clone())
                            .unwrap_or("".to_string());
                        let last_name = attending_opt
                            .map(|a| a.name.last_name.clone())
                            .unwrap_or("".to_string());
                        let dietary_notes = attending_opt
                            .map(|a| a.dietary_notes.clone())
                            .unwrap_or("".to_string());
                        let rendered_guest = guest_template
                            .replace("$num", &(guest_num + 1).to_string())
                            .replace("$index", &guest_num.to_string())
                            .replace("$first_name", &first_name)
                            .replace("$last_name", &last_name)
                            .replace("$dietary_notes", &dietary_notes);
                        guests_builder.push_str(&rendered_guest);
                        guests_builder
                    },
                );

                form_template
                    .replace("$token", &token)
                    .replace("$checked", &checked)
                    .replace("$guests", &guests)
                    .replace("$email", &email)
                    .replace("$other_notes", &other_notes)
            },
        };

        let response = server::Response::new()
            .with_body(Body::from(rendered));
        Box::new(future::ok(response))
    }
}

impl Service for RsvpService {
    type Request = server::Request<Body>;
    type Response = server::Response<Body>;
    type Error = HyperError;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, request: Self::Request) -> Self::Future {
        let uri = request.uri().clone();
        println!("{} {}", request.method(), uri);

        match request.method() {
            Method::Get => RsvpService::handle_static(uri),

            Method::Post => {
                // TODO(jacob): Could we put a lifetime on RsvpService instead of cloning these?
                let account_data_clone_1 = self.account_data.clone();
                let account_data_clone_2 = self.account_data.clone();
                let datastore_client_clone_1 = self.datastore_client.clone();
                let datastore_client_clone_2 = self.datastore_client.clone();
                let rsvp_credentials = self.rsvp_credentials.clone();

                let response_future = request.body().concat2().and_then(move |data| {
                    let data_str = str::from_utf8(&data).unwrap_or(
                        format!("unparseable - {:?}", data).as_str()
                    ).to_string();
                    println!("received POST data: {}", data_str);

                    RsvpService::handle_login(
                        account_data_clone_1,
                        datastore_client_clone_1,
                        rsvp_credentials,
                        &data,
                    ).or_else(move || {
                        RsvpService::handle_submission(
                            account_data_clone_2,
                            datastore_client_clone_2,
                            &data,
                        )
                    }).unwrap_or_else(|| {
                        println!("invalid POST data: {}", data_str);
                        let response = server::Response::new()
                            .with_status(StatusCode::BadRequest)
                            .with_body(Body::from("Bad Request"));
                        Box::new(future::ok(response))
                    })
                });
                Box::new(response_future)
            },

            _ => {
                let response = server::Response::new()
                    .with_status(StatusCode::MethodNotAllowed)
                    .with_body(Body::from("Method Not Allowed"));
                Box::new(future::ok(response))
            },
        }
    }
}

fn main() {
    let account_file = File::open("keys/application-datastore-user.json")
        .expect("failed to open account details file");
    let account_details = serde_json::from_reader(account_file)
        .expect("failed to parse account details");
    let account_private_key = fs::read("keys/private_rsa_key.der")
        .expect("Failed to read account private key");
    let account_public_key = fs::read("keys/public_rsa_key.der")
        .expect("Failed to read account public key");
    let account_data = AccountData {
        details: account_details,
        private_key: account_private_key,
        public_key: account_public_key,
    };

    let rsvp_credentials_file = File::open("keys/rsvp_credentials.json")
        .expect("failed to open rsvp credentials file");
    let rsvp_credentials: RsvpCredentials = serde_json::from_reader(rsvp_credentials_file)
        .expect("failed to parse rsvp credentials");

    let mut event_loop = Core::new().expect("unable to create event loop");
    let event_loop_handle = event_loop.handle();
    let https = HttpsConnector::new(2, &event_loop_handle).expect("TLS initialization failed");
    let client = Client::configure().connector(https).build(&event_loop_handle);

    let socket_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        8080,
    );

    let service = RsvpService::new(client, account_data, rsvp_credentials);
    let server = Http::new()
        .serve_addr_handle(&socket_addr, &event_loop_handle, move || Ok(service.clone()))
        .expect("unable to bind http server");
    let inner_event_loop_handle = event_loop_handle.clone();

    println!("running...");
    let connection_handle_future = server.for_each(move |connection| {
        let connection_future = connection
            .map(|_| ())
            .map_err(|error| eprintln!("server error: {}", error));
        inner_event_loop_handle.spawn(connection_future);
        Ok(())
    }).map_err(|error| eprintln!("server spawn error: {}", error));
    event_loop_handle.spawn(connection_handle_future);
    event_loop.run(future::empty::<(),()>()).expect("failed to start event loop");
}
