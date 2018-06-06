extern crate hyper;
extern crate hyper_tls;
extern crate jsonwebtoken as jwt;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;

use hyper::{Body, Client, Request, Uri};
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use hyper::rt::{self, Future, Stream};
use hyper_tls::HttpsConnector;
use jwt::{Algorithm, Header};
use std::env;
use std::fs::{self, File};
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize, Serialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
}

#[derive(Deserialize, Serialize)]
struct AccountDetails {
    project_id: String,
    private_key_id: String,
    client_email: String,
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

fn build_query_request(account_details: AccountDetails, query: String) -> Request<Body> {
    let uri = format!(
        "{}/v1/projects/{}:runQuery",
        DATASTORE_HOST,
        account_details.project_id,
    ).parse::<Uri>().expect("Unable to parse query uri");

    let token = get_token(account_details);

    Request::post(uri)
        .header(
            ACCEPT,
            HeaderValue::from_static("application/json"),
        )
        .header(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token))
                .expect("Unable to build Authorization header"),
        )
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )
        .body(Body::from(query))
        .expect("Failed to construct POST request")
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

fn main() {
    let args = env::args().collect::<Vec<String>>();
    let first_name = &args[1];
    let last_name = &args[2];

    let account_file = File::open("keys/application-datastore-user.json")
        .expect("Failed to open account details file");
    let account_details = serde_json::from_reader(account_file)
        .expect("Failed to parse account details");

    let https = HttpsConnector::new(2).expect("TLS initialization failed");
    let client = Client::builder().build(https);

    let query = query_for_name(first_name, last_name);
    let request = build_query_request(account_details, query);

    let response_future = rt::lazy(move || {
        client
            .request(request)
            .and_then(|response| {
                response.into_body().concat2()
            }).map(|data| {
                println!("{}", str::from_utf8(&data).unwrap());
            }).map_err(|error| {
                eprintln!("Error {}", error);
            })
    });
    rt::run(response_future);
}
