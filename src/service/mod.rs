use bytes::Bytes;
use futures::Future;
use futures::future;
use futures::stream::Stream;
use hyper::{Body, Client, Method, StatusCode, Uri};
use hyper::{Error as HyperError};
use hyper::client::{self, HttpConnector};
use hyper::header::{self, Accept, Authorization, Bearer, ContentType};
use hyper::mime::APPLICATION_JSON;
use hyper::server::{self, Service};
use hyper_tls::HttpsConnector;
use itertools;
use jsonwebtoken::{self, Algorithm, Header};
use serde_json::{self, Value};
use std::collections::HashMap;
use std::io::Read;
use std::iter::FromIterator;
use std::fs::File;
use std::io::BufReader;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};
use url::form_urlencoded;

pub mod form;

use {AccountData, RsvpCredentials};
use datastore::client::{CommitResult, RsvpQueryResult};
use model::Rsvp;

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

#[derive(Clone)]
pub struct RsvpService {
    datastore_client: Client<HttpsConnector<HttpConnector>, Body>,
    account_data: AccountData,
    rsvp_credentials: RsvpCredentials,
}

impl RsvpService {
    pub fn new(
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

        jsonwebtoken::encode(&jwt_header, &claims, &account_data.private_key)
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

                        RsvpQueryResult::Single(rsvp) => RsvpService::render_form(
                            &account_data,
                            rsvp,
                            None,
                            StatusCode::Ok,
                        ),
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
        // TODO(jacob): There are a bunch of clones in this function. They would seem to
        //      be removable by just having the closures borrow their values instead of
        //      taking ownership, but that may not be possible due to the static lifetime
        //      of the futures these closures are operating over. If it isn't possible,
        //      we should just have Rsvp implement Copy so this happens automatically.
        let account_data1 = account_data.clone();
        let account_data2 = account_data.clone();
        let account_data3 = account_data.clone();
        let rsvp1 = Rsvp::from_form_data(&account_data, data)?;
        let rsvp2 = rsvp1.clone();
        let rsvp3 = rsvp1.clone();
        let rsvp4 = rsvp1.clone();
        let transaction_request = RsvpService::build_transaction_request(&account_data);

        let response_future = datastore_client.request(transaction_request)
            .and_then(move |transaction_response| {
                transaction_response.body().concat2().and_then(move |raw_result| {
                    let transaction_string = str::from_utf8(&raw_result)
                        .expect("unable to parse transaction response");
                    let transaction_json = serde_json::from_str::<Value>(transaction_string)
                        .expect("unable to parse transaction json");

                    transaction_json["transaction"].as_str().map_or_else(
                        || {
                            let message = RsvpService::render_message(
                                "Error saving rsvp, please try again later  and contact \
                                Jacob if this error persists.",
                                true,
                            );
                            RsvpService::render_form(
                                &account_data,
                                rsvp1,
                                Some(&message),
                                StatusCode::InternalServerError,
                            )
                        },

                        |transaction_id| {
                            let commit_request = RsvpService::build_commit_request(
                                &account_data1,
                                transaction_id,
                                rsvp2,
                            );
                            let response_future = datastore_client.request(commit_request)
                                .and_then(move |commit_response| {
                                    commit_response.body().concat2().and_then(move |raw_commit_result| {
                                        let commit_string = str::from_utf8(&raw_commit_result)
                                            .expect("unable to parse commit response");
                                        let commit_json = serde_json::from_str::<Value>(commit_string)
                                            .expect("unable to parse commit json");

                                        CommitResult::from_json(&commit_json).map_or_else(
                                            || {
                                                let message = RsvpService::render_message(
                                                    "Error saving rsvp, please try again later \
                                                    and contact Jacob if this error persists.",
                                                    true,
                                                );
                                                RsvpService::render_form(
                                                    &account_data2,
                                                    rsvp3,
                                                    Some(&message),
                                                    StatusCode::InternalServerError,
                                                )
                                            },

                                            |commit_result| {
                                                println!(
                                                    "successfully saved rsvp with result: {:?}",
                                                    commit_result,
                                                );
                                                let message = RsvpService::render_message(
                                                    "Rsvp saved successfully!",
                                                    false,
                                                );
                                                RsvpService::render_form(
                                                    &account_data3,
                                                    rsvp4,
                                                    Some(&message),
                                                    StatusCode::Ok,
                                                )
                                            },
                                        )
                                    })
                                });
                            Box::new(response_future)
                        },
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
                invited_count,
            } => {
                let empty = Rsvp::Empty {
                    key: key.clone(),
                    invited: invited.to_vec(),
                    invited_count: *invited_count,
                };
                empty.to_json()
            }
        };

        let mut header = Header::default();
        header.alg = Algorithm::RS256;
        jsonwebtoken::encode(&header, &empty_rsvp_json, &account_data.private_key)
            .expect("Error encoding auth token")
    }

    fn render_message(message: &str, error: bool) -> String {
        let div = if error { "<div style=\"color: red\">" } else { "<div>" };
        format!("{}{}</div><a href=\"/\">Return home</a>", div, message)
    }

    fn render_form(
        account_data: &AccountData,
        rsvp: Rsvp,
        message_opt: Option<&str>,
        status_code: StatusCode,
    ) -> ResponseFuture {
        let form_file = File::open("www/rsvp2.html").expect("failed to open rsvp form template");
        let mut form_reader = BufReader::new(form_file);
        let mut form_template = String::new();
        form_reader.read_to_string(&mut form_template).expect("failed to read form template");

        let guest_file = File::open("templates/guest.html").expect("failed to open guest template");
        let mut guest_reader = BufReader::new(guest_file);
        let mut guest_template = String::new();
        guest_reader.read_to_string(&mut guest_template).expect("failed to read guest template");

        let token = RsvpService::get_auth_token(account_data, &rsvp);
        let message = message_opt.unwrap_or("");
        let rendered = match rsvp {
            Rsvp::Empty {
                key: _,
                invited: _,
                invited_count,
            } => {
                let guests = (0..invited_count).fold(
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
                    .replace("$message", message)
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
                invited: _,
                other_notes,
                invited_count,
            } => {
                let checked = if going { "checked" } else { "" };
                let guests = (0..invited_count).fold(
                    String::new(),
                    |mut guests_builder, guest_num| {
                        let attending_opt = attending.get(guest_num as usize);
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
                    .replace("$message", message)
                    .replace("$token", &token)
                    .replace("$checked", &checked)
                    .replace("$guests", &guests)
                    .replace("$email", &email)
                    .replace("$other_notes", &other_notes)
            },
        };

        let response = server::Response::new()
            .with_status(status_code)
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

