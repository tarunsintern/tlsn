/// This example shows how to notarize Twitter DMs.
///
/// The example uses the notary server implemented in ../../../notary-server
use futures::AsyncWriteExt;
use hyper::{body::to_bytes, client::conn::Parts, Body, Request, StatusCode};
use mpz_core::serialize::CanonicalSerialize;
use rustls::{Certificate, ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::{env, ops::Range, str, sync::Arc};
use tlsn_core::proof::TlsProof;
use tokio::{io::AsyncWriteExt as _, net::TcpStream};
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use tlsn_prover::tls::{Prover, ProverConfig};

// Setting of the application server
const SERVER_DOMAIN: &str = "twitter.com";
const ROUTE: &str = "i/api/1.1/dm/conversation";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

// Setting of the notary server — make sure these are the same with those in ../../../notary-server
const NOTARY_HOST: &str = "127.0.0.1";
const NOTARY_PORT: u16 = 7047;

// Configuration of notarization
const NOTARY_MAX_TRANSCRIPT_SIZE: usize = 16384;

/// Response object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionResponse {
    pub session_id: String,
}

/// Request object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionRequest {
    pub client_type: ClientType,
    /// Maximum transcript size in bytes
    pub max_transcript_size: Option<usize>,
}

/// Types of client that the prover is using
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
    /// Client that has access to the transport layer
    Tcp,
    /// Client that cannot directly access transport layer, e.g. browser extension
    Websocket,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Load secret variables frome environment for twitter server connection
    dotenv::dotenv().ok();
    let conversation_id = env::var("CONVERSATION_ID").unwrap();
    let client_uuid = env::var("CLIENT_UUID").unwrap();
    let auth_token = env::var("AUTH_TOKEN").unwrap();
    let access_token = env::var("ACCESS_TOKEN").unwrap();
    let guest_token = env::var("GUEST_TOKEN").unwrap();
    let csrf_token = env::var("CSRF_TOKEN").unwrap();

    let (notary_tls_socket, session_id) = setup_notary_connection().await;

    // Basic default prover config using the session_id returned from /session endpoint just now
    let config = ProverConfig::builder()
        .id(session_id)
        .server_dns(SERVER_DOMAIN)
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(config)
        .setup(notary_tls_socket.compat())
        .await
        .unwrap();

    // Connect to the Server via TCP. This is the TLS client socket.
    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) = hyper::client::conn::handshake(tls_connection.compat())
        .await
        .unwrap();

    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

    // print

    let url: &str = "https://api.twitter.com/graphql/5GOHgZe-8U2j5sVHQzEm9A/TweetResultByRestId?variables=%7B%22tweetId%22%3A+%221751364627697385745%22%2C+%22withCommunity%22%3A+false%2C+%22includePromotedContent%22%3A+true%2C+%22withVoice%22%3A+false%7D&features=%7B%22creator_subscriptions_tweet_preview_api_enabled%22%3A+true%2C+%22c9s_tweet_anatomy_moderator_badge_enabled%22%3A+true%2C+%22tweetypie_unmention_optimization_enabled%22%3A+true%2C+%22responsive_web_edit_tweet_api_enabled%22%3A+true%2C+%22graphql_is_translatable_rweb_tweet_is_translatable_enabled%22%3A+true%2C+%22view_counts_everywhere_api_enabled%22%3A+true%2C+%22longform_notetweets_consumption_enabled%22%3A+true%2C+%22responsive_web_twitter_article_tweet_consumption_enabled%22%3A+false%2C+%22tweet_awards_web_tipping_enabled%22%3A+false%2C+%22responsive_web_home_pinned_timelines_enabled%22%3A+true%2C+%22freedom_of_speech_not_reach_fetch_enabled%22%3A+true%2C+%22standardized_nudges_misinfo%22%3A+true%2C+%22tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled%22%3A+true%2C+%22longform_notetweets_rich_text_read_enabled%22%3A+true%2C+%22longform_notetweets_inline_media_enabled%22%3A+true%2C+%22responsive_web_graphql_exclude_directive_enabled%22%3A+true%2C+%22verified_phone_label_enabled%22%3A+false%2C+%22responsive_web_media_download_video_enabled%22%3A+false%2C+%22responsive_web_graphql_skip_user_profile_image_extensions_enabled%22%3A+false%2C+%22responsive_web_graphql_timeline_navigation_enabled%22%3A+true%2C+%22responsive_web_enhance_cards_enabled%22%3A+false%7D";

    // Build the HTTP request to fetch the DMs
    println!("https://{SERVER_DOMAIN}/{ROUTE}/{conversation_id}.json");
    // "https://api.twitter.com/1.1/statuses/show/1717234287689584827.json"

    let request = Request::builder()
        .uri(format!(
            "{}", url
        ))
        // .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        .header("Accept-Language","en-PK,en;q=0.9")
        .header("Referer", "https://twitter.com/")
        // .header("Accept-Encoding", "identity")
        // .header("Connection", "close")
        .header("User-Agent", USER_AGENT)
        .header("Authorization", format!("Bearer {access_token}"))
        // .header(
        //     "Cookie",
        //     format!("auth_token={auth_token}; ct0={csrf_token}"),
        // )
        // .header("Authority", SERVER_DOMAIN)
        // .header("X-Twitter-Auth-Type", "OAuth2Session")
        .header("X-Twitter-Client-Language", "en")
        .header("X-Guest-Token", guest_token)
        .header("x-twitter-active-user", "yes")
        // .header("X-Client-Uuid", client_uuid.clone())
        .header("X-Csrf-Token", csrf_token.clone())
        .body(Body::empty())
        .unwrap();

    debug!("Sending request");

    let response = request_sender.send_request(request).await.unwrap();

    println!("Response {:?}", response);

    debug!("Sent request");

    assert!(response.status() == StatusCode::OK, "{}", response.status());

    debug!("Request OK");

    // Pretty printing :)
    let payload = to_bytes(response.into_body()).await.unwrap().to_vec();
    let parsed =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&payload)).unwrap();
    debug!("{}", serde_json::to_string_pretty(&parsed).unwrap());

    // Close the connection to the server
    let mut client_socket = connection_task.await.unwrap().unwrap().io.into_inner();
    client_socket.close().await.unwrap();

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await.unwrap().unwrap();

    println!("prover task completed, starting notarization ...",);

    // Prepare for notarization
    let mut prover = prover.start_notarize();

    println!("FJAAK: transcript: {:?}", prover.recv_transcript().data());

    // Identify the ranges in the transcript that contain secrets
    let (public_ranges, private_ranges) = find_ranges(
        prover.sent_transcript().data(),
        &[
            access_token.as_bytes(),
            auth_token.as_bytes(),
            csrf_token.as_bytes(),
            client_uuid.as_bytes(),
        ],
    );

    // Identify the ranges in the inbound data which contain data which we want to disclose
    let (recv_public_ranges, recv_private_ranges) = find_ranges_public(
        prover.recv_transcript().data(),
        &[
            // Redact the value of the title. It will NOT be disclosed.
            "rest_id\":\"1751364627697385745\"".as_bytes(),
            // "\"favorite_count\":3".as_bytes(),
        ],
    );

    println!("FJAAK: range: {:?}, {:?}", recv_public_ranges,recv_private_ranges );

    let recv_len = prover.recv_transcript().data().len();

    println!("FJAAK: recv_len: {:?}", recv_len);

    let builder = prover.commitment_builder();

    // Commit to send public data and collect commitment ids for the outbound transcript
    let mut sent_commitments = public_ranges
        .iter()
        .map(|range| builder.commit_sent(range.clone()).unwrap())
        .collect::<Vec<_>>();
    // Commit to private data. This is not needed for proof creation but ensures the data
    // is in the notarized session file for optional future disclosure.
    // private_ranges.iter().for_each(|range| {
    //     builder.commit_sent(range.clone()).unwrap();
    // });
    // Commit to each range of the public inbound data which we want to disclose
    let recv_commitments: Vec<_> = recv_public_ranges
        .iter()
        .map(|r| builder.commit_recv(r.clone()).unwrap())
        .collect();
    // // Commit to the received (public) data.
    // commitment_ids.push(builder.commit_recv(0..recv_len).unwrap());


    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    debug!("Notarization complete!");

    // Dump the notarized session to a file
    let mut file = tokio::fs::File::create("twitter_dm.json").await.unwrap();
    file.write_all(
        serde_json::to_string_pretty(&notarized_session)
            .unwrap()
            .as_bytes(),
    )
    .await
    .unwrap();

    let session_proof = notarized_session.session_proof();

    let mut proof_builder = notarized_session.data().build_substrings_proof();
    for commitment_id in sent_commitments {
        proof_builder.reveal(commitment_id).unwrap();
    }
    for commitment_id in recv_commitments {
        proof_builder.reveal(commitment_id).unwrap();
    }
    let substrings_proof = proof_builder.build().unwrap();

    let proof = TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };

    // Dump the proof to a file.
    let mut file = tokio::fs::File::create("twitter_dm_proof.json")
        .await
        .unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();
}

async fn setup_notary_connection() -> (tokio_rustls::client::TlsStream<TcpStream>, String) {
    // Connect to the Notary via TLS-TCP
    let pem_file = str::from_utf8(include_bytes!(
        "../../../notary-server/fixture/tls/rootCA.crt"
    ))
    .unwrap();
    let mut reader = std::io::BufReader::new(pem_file.as_bytes());
    let mut certificates: Vec<Certificate> = rustls_pemfile::certs(&mut reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let certificate = certificates.remove(0);

    let mut root_store = RootCertStore::empty();
    root_store.add(&certificate).unwrap();

    let client_notary_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let notary_connector = TlsConnector::from(Arc::new(client_notary_config));

    let notary_socket = tokio::net::TcpStream::connect((NOTARY_HOST, NOTARY_PORT))
        .await
        .unwrap();

    let notary_tls_socket = notary_connector
        // Require the domain name of notary server to be the same as that in the server cert
        .connect("tlsnotaryserver.io".try_into().unwrap(), notary_socket)
        .await
        .unwrap();

    // Attach the hyper HTTP client to the notary TLS connection to send request to the /session endpoint to configure notarization and obtain session id
    let (mut request_sender, connection) = hyper::client::conn::handshake(notary_tls_socket)
        .await
        .unwrap();

    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

    // Build the HTTP request to configure notarization
    let payload = serde_json::to_string(&NotarizationSessionRequest {
        client_type: ClientType::Tcp,
        max_transcript_size: Some(NOTARY_MAX_TRANSCRIPT_SIZE),
    })
    .unwrap();

    let request = Request::builder()
        .uri(format!("https://{NOTARY_HOST}:{NOTARY_PORT}/session"))
        .method("POST")
        .header("Host", NOTARY_HOST)
        // Need to specify application/json for axum to parse it as json
        .header("Content-Type", "application/json")
        .body(Body::from(payload))
        .unwrap();

    debug!("Sending configuration request");

    let configuration_response = request_sender.send_request(request).await.unwrap();

    debug!("Sent configuration request");

    assert!(configuration_response.status() == StatusCode::OK);

    debug!("Response OK");

    // Pretty printing :)
    let payload = to_bytes(configuration_response.into_body())
        .await
        .unwrap()
        .to_vec();
    let notarization_response =
        serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(&payload))
            .unwrap();

    debug!("Notarization response: {:?}", notarization_response,);

    // Send notarization request via HTTP, where the underlying TCP connection will be extracted later
    let request = Request::builder()
        // Need to specify the session_id so that notary server knows the right configuration to use
        // as the configuration is set in the previous HTTP call
        .uri(format!(
            "https://{}:{}/notarize?sessionId={}",
            NOTARY_HOST,
            NOTARY_PORT,
            notarization_response.session_id.clone()
        ))
        .method("GET")
        .header("Host", NOTARY_HOST)
        .header("Connection", "Upgrade")
        // Need to specify this upgrade header for server to extract tcp connection later
        .header("Upgrade", "TCP")
        .body(Body::empty())
        .unwrap();

    debug!("Sending notarization request");

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent notarization request");

    assert!(response.status() == StatusCode::SWITCHING_PROTOCOLS);

    debug!("Switched protocol OK");

    // Claim back the TLS socket after HTTP exchange is done
    let Parts {
        io: notary_tls_socket,
        ..
    } = connection_task.await.unwrap().unwrap();

    (notary_tls_socket, notarization_response.session_id)
}

/// Find the ranges of the public and private parts of a sequence.
///
/// Returns a tuple of `(public, private)` ranges.
fn find_ranges(seq: &[u8], sub_seq: &[&[u8]]) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
    let mut private_ranges = Vec::new();
    for s in sub_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx..(idx + w.len()));
            }
        }
    }

    let mut sorted_ranges = private_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut public_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            public_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }

    if last_end < seq.len() {
        public_ranges.push(last_end..seq.len());
    }

    (public_ranges, private_ranges)
}

/// Find the ranges of the public and private parts of a sequence.
///
/// Returns a tuple of `(public, private)` ranges.
fn find_ranges_public(seq: &[u8], sub_seq: &[&[u8]]) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
    let mut public_ranges = Vec::new();
    for s in sub_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                public_ranges.push(idx..(idx + w.len()));
            }
        }
    }

    let mut sorted_ranges = public_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut private_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            private_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }

    if last_end < seq.len() {
        private_ranges.push(last_end..seq.len());
    }

    (public_ranges, private_ranges)
}
