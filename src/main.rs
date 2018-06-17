extern crate bytes;
extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate itertools;
extern crate jsonwebtoken as jwt;
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
use jwt::{Algorithm, Header};
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
        let param_map = form_urlencoded::parse(form_data).collect::<HashMap<_, _>>();
        let first_name = param_map.get("first_name")?;
        let last_name = param_map.get("last_name")?;
        let password = param_map.get("password")?;

        let login_data = LoginData {
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
            password: password.to_string(),
        };
        Some(login_data)
    }
}

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
    // GCP datastore returns integers encoded as strings.
    json["integerValue"].as_str().and_then(|s| s.parse().ok())
}

fn parse_string_value(json: &Value) -> Option<String> {
    json["stringValue"].as_str().map(|s| s.to_string())
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
}

// TODO(jacob): Is there some way to de-dupe common fields here?
#[derive(Clone, Debug)]
enum Rsvp<'a> {
    /* A database entry for someone who has not yet RSVPed */
    Empty {
        key: &'a Value,
        invited: Vec<Name>,
        plus_ones: u8,
    },
    /* A database entry for someone who has RSVPed */
    Full {
        key: &'a Value,
        attending: Vec<Guest>,
        email: String,
        going: bool,
        invited: Vec<Name>,
        other_notes: String,
        plus_ones: u8,
    },
}

impl<'a> Rsvp<'a> {
    // TODO(jacob): Figure out how to define Deserialize/Serialize for the datastore json
    //      format.
    fn from_json(json: &Value) -> Option<Rsvp> {
        let key = &json["entity"]["key"];
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
}

#[derive(Debug)]
enum RsvpQueryResult<'a> {
    NotFound,
    Single(Rsvp<'a>),
    Multiple(Vec<Rsvp<'a>>),
}

impl<'a> RsvpQueryResult<'a> {
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

    fn query_for_name(first_name: &str, last_name: &str) -> String {
        json!({
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
        }).to_string()
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

    fn build_query_request(account_data: &AccountData, query: String) -> client::Request<Body> {
        let uri = format!(
            "{}/v1/projects/{}:runQuery",
            DATASTORE_HOST,
            account_data.details.project_id,
        ).parse().expect("Unable to parse query uri");

        let token = RsvpService::get_datastore_token(account_data);

        let mut request = client::Request::new(Method::Post, uri);
        request.headers_mut().set(Accept(vec![header::qitem(APPLICATION_JSON)]));
        request.headers_mut().set(Authorization(Bearer { token: token }));
        request.headers_mut().set(ContentType(APPLICATION_JSON));
        request.set_body(Body::from(query));
        request
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
            let query = RsvpService::query_for_name(
                &login_data.first_name,
                &login_data.last_name,
            );
            let request = RsvpService::build_query_request(&account_data, query);

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

    fn get_auth_token(
        account_data: &AccountData,
        key: &Value,
    ) -> String {
        let mut header = Header::default();
        header.alg = Algorithm::RS256;
        jwt::encode(&header, key, &account_data.private_key)
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

        let rendered = match rsvp {
            Rsvp::Empty {
                key,
                invited,
                plus_ones,
            } => {
                let token = RsvpService::get_auth_token(account_data, key);
                let guests = (0..(invited.len() + plus_ones as usize)).fold(
                    String::new(),
                    |mut guests_builder, guest_num| {
                        let rendered_guest = guest_template
                            .replace("$num", &(guest_num + 1).to_string())
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
                key,
                attending,
                email,
                going,
                invited,
                other_notes,
                plus_ones,
            } => {
                let token = RsvpService::get_auth_token(account_data, key);
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
                let account_data = self.account_data.clone();
                let datastore_client = self.datastore_client.clone();
                let rsvp_credentials = self.rsvp_credentials.clone();

                let response_future = request.body().concat2().and_then(move |data| {
                    RsvpService::handle_login(
                        account_data,
                        datastore_client,
                        rsvp_credentials,
                        &data,
                    ).unwrap_or_else(|| {
                        println!(
                            "invalid login attempt: {}",
                            str::from_utf8(&data).unwrap_or(
                                format!("invalid login attempt (unparseable): {:?}", data).as_str()
                            ),
                        );
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
    let account_data = AccountData {
        details: account_details,
        private_key: account_private_key,
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
