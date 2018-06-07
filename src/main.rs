extern crate bytes;
extern crate futures;
extern crate hyper;
extern crate hyper_tls;
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
use hyper::{Body, Client, Method, StatusCode};
use hyper::Error;
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

#[derive(Clone, Deserialize, Serialize)]
struct RsvpCredentials {
    admin: String,
    user: String,
}

struct LoginData {
    first_name: String,
    last_name: String,
    password: String,
}

impl LoginData {
    // TODO(jacob): validate this...
    fn from_form_data(form_data: &[u8]) -> LoginData {
        let param_map = form_urlencoded::parse(form_data).collect::<HashMap<_, _>>();
        let first_name = param_map.get("first_name")
            .expect("required param `first_name` not found")
            .to_string();
        let last_name = param_map.get("last_name")
            .expect("required param `last_name` not found")
            .to_string();
        let password = param_map.get("password")
            .expect("required param `password` not found")
            .to_string();

        LoginData {
            first_name: first_name,
            last_name: last_name,
            password: password,
        }
    }
}

static DATASTORE_API: &'static str = "google.datastore.v1.Datastore";
static DATASTORE_HOST: &'static str = "https://datastore.googleapis.com";

fn get_token(account_details: AccountDetails) -> String {
    let private_key = fs::read("keys/private_rsa_key.der")
        .expect("Failed to read private key");
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Error getting unix timestamp")
        .as_secs();

    let mut jwt_header = Header::default();
    jwt_header.alg = Algorithm::RS256;
    jwt_header.kid = Some(account_details.private_key_id);
    jwt_header.typ = Some("JWT".to_string());

    let claims = Claims {
        iss: account_details.client_email.clone(),
        sub: account_details.client_email.clone(),
        aud: format!("{}/{}", DATASTORE_HOST, DATASTORE_API),
        iat: time,
        exp: time + 3600,
    };

    jwt::encode(&jwt_header, &claims, &private_key).expect("Error encoding json web token")
}

fn build_query_request(account_details: AccountDetails, query: String) -> client::Request<Body> {
    let uri = format!(
        "{}/v1/projects/{}:runQuery",
        DATASTORE_HOST,
        account_details.project_id,
    ).parse().expect("Unable to parse query uri");

    let token = get_token(account_details);

    let mut request = client::Request::new(Method::Post, uri);
    request.headers_mut().set(Accept(vec![header::qitem(APPLICATION_JSON)]));
    request.headers_mut().set(Authorization(Bearer { token: token }));
    request.headers_mut().set(ContentType(APPLICATION_JSON));
    request.set_body(Body::from(query));
    request
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

#[derive(Clone)]
struct RsvpService {
    datastore_client: Client<HttpsConnector<HttpConnector>, Body>,
    account_details: AccountDetails,
    rsvp_credentials: RsvpCredentials,
}

impl RsvpService {
    fn new(
        datastore_client: Client<HttpsConnector<HttpConnector>, Body>,
        account_details: AccountDetails,
        rsvp_credentials: RsvpCredentials,
    ) -> RsvpService {
        RsvpService {
            datastore_client: datastore_client,
            account_details: account_details,
            rsvp_credentials: rsvp_credentials,
        }
    }
}

impl Service for RsvpService {
    type Request = server::Request<Body>;
    type Response = server::Response<Body>;
    type Error = hyper::Error;
    type Future = Box<Future<Item = Self::Response, Error = self::Error>>;

    fn call(&self, request: Self::Request) -> Self::Future {
        let uri = request.uri().clone();
        println!("{} {}", request.method(), uri);

        match request.method() {
            Method::Post => {
                // TODO(jacob): Could we put a lifetime on RsvpService instead of cloning these?
                let account_details = self.account_details.clone();
                let datastore_client = self.datastore_client.clone();

                let response_future = request.body().concat2().and_then(move |data| {
                    let login_data = LoginData::from_form_data(&data);
                    let query = query_for_name(&login_data.first_name, &login_data.last_name);
                    let request = build_query_request(account_details, query);

                    datastore_client.request(request).and_then(move |response| {
                        response.body().concat2().map(move |query_result| {
                            let rsvp_entry = str::from_utf8(&query_result)
                                .expect("unable to parse database rsvp entry");
                            println!("{}", rsvp_entry);

                            let file = File::open(format!("www/rsvp2.html"))
                                .expect("failed to open rsvp form file");
                            let mut buf_reader = BufReader::new(file);
                            let mut template = String::new();
                            buf_reader.read_to_string(&mut template)
                                .expect("failed to read rsvp form file");
                            let rendered = template
                                .replace("$first_name", &login_data.first_name)
                                .replace("$last_name", &login_data.last_name);

                            server::Response::new()
                                .with_body(Body::from(rendered))
                        })
                    })
                });
                Box::new(response_future)
            },

            Method::Get => {
                let file = File::open(format!("www{}", request.uri()))
                    .expect(&format!("failed to open file for request: {}", request.uri()));
                let file_bytes = file.bytes().map(|byte_result| {
                    byte_result.expect(&format!("failed to read file for request: {}", request.uri()))
                });
                let bytes = Bytes::from_iter(file_bytes);
                Box::new(future::ok(server::Response::new().with_body(Body::from(bytes))))
            },

            _ => {
                let response = server::Response::new()
                    .with_status(StatusCode::MethodNotAllowed)
                    .with_body(Body::from("Method not allowed"));
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

    let service = RsvpService::new(client, account_details, rsvp_credentials);
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
