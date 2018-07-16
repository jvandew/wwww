extern crate bytes;
extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate itertools;
extern crate jsonwebtoken;
extern crate regex;
extern crate tokio_core;
extern crate url;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate serde_json;

use futures::Future;
use futures::future;
use futures::stream::Stream;
use hyper::Client;
use hyper::server::Http;
use hyper_tls::HttpsConnector;
use std::fs::{self, File};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str;
use tokio_core::reactor::Core;

mod datastore;
mod model;
mod service;

use service::RsvpService;

#[derive(Clone, Deserialize, Serialize)]
struct AccountDetails {
    project_id: String,
    private_key_id: String,
    client_email: String,
}

#[derive(Clone)]
pub struct AccountData {
    details: AccountDetails,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct RsvpCredentials {
    admin: String,
    user: String,
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
