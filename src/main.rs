// Copyright (c) 2022 ClSlaid <cailue@bupt.edu.cn>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// TODO: refract into a clap application
use std::{
    fs::File,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::mpsc,
};
use tokio_rustls::rustls::{Certificate, PrivateKey};
use tracing::instrument;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};
use tsein_dns::{
    cache::DnsCache,
    comm::{
        client::QuicForwarder, QuicService, Task, TcpService, TlsListener, TlsService, UdpService,
    },
};

const CACHE_SIZE: usize = 9192;

static KEY_PATH: &str = "secret/localhost+2-key.pem";
static CERT_PATH: &str = "secret/localhost+2.pem";

fn load_certs(path: &str) -> std::io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &str) -> std::io::Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}

async fn transaction(mut tasks: mpsc::UnboundedReceiver<Task>, cache: DnsCache) {
    tracing::info!("initiated transaction layer");
    let lookups = futures::stream::FuturesUnordered::new();
    while let Some(task) = tasks.recv().await {
        tracing::debug!("received task");

        match task {
            Task::Query(query, ans_sender) => {
                tracing::debug!("looking up local cache for query: {}", query.get_name());
                let mut c = cache.clone();
                let lookup = tokio::spawn(async move {
                    let name = query.get_name();
                    let answers = c.get(query).await;
                    for ans in answers.into_iter() {
                        let _ = ans_sender.send(ans);
                    }
                    tracing::debug!("transaction on query {} successful!", name);
                });
                lookups.push(lookup);
            }
        };
    }
    for lookup in lookups {
        let _ = tokio::join!(lookup);
    }
}

fn main() {
    // init logger
    if let Ok(local_timer) = fmt::time::OffsetTime::local_rfc_3339() {
        tracing_subscriber::registry()
            .with(fmt::layer().with_timer(local_timer))
            .init();
    } else {
        let sys_timer = fmt::time::SystemTime;
        tracing_subscriber::registry()
            .with(fmt::layer().with_timer(sys_timer))
            .init();
    }
    tracing::info!(
        "Starting {}, version {}, author {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_AUTHORS")
    );
    tracing::info!("initializing tokio runtime");

    let upstream_domain: &str = "dns-unfiltered.adguard.com";
    let upstream_addr: SocketAddr = SocketAddr::new(
        IpAddr::from(Ipv6Addr::new(0x2a10, 0x50c0, 0, 0, 0, 0, 0x1, 0xff)),
        853,
    );

    run(upstream_domain, upstream_addr);
}

#[instrument]
#[tokio::main]
async fn run(upstream_domain: &'static str, upstream_addr: SocketAddr) {
    // load ssl keys and certs
    let mut keys = match load_keys(KEY_PATH) {
        Ok(keys) => keys,
        Err(e) => {
            tracing::error!("cannot load keys from {}: {}", KEY_PATH, e);
            return;
        }
    };
    let certs = match load_certs(CERT_PATH) {
        Ok(certs) => certs,
        Err(e) => {
            tracing::error!("cannot load certs from {}: {}", CERT_PATH, e);
            return;
        }
    };

    let mut roots = rustls::RootCertStore::empty();
    for cert in
        rustls_native_certs::load_native_certs().expect("failed to read system native certificates")
    {
        roots.add(&Certificate(cert.0)).unwrap();
    }

    let mut serv_config = match rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
    {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::error!("cannot generate server config: {}", e);
            return;
        }
    };

    serv_config.alpn_protocols = vec![
        Vec::from(&b"dot"[..]),
        Vec::from(&b"doq"[..]),
        Vec::from(&b"doq-i11"[..]),
    ];
    let serv_config = Arc::new(serv_config);

    // init UDP serving ports
    tracing::info!("binding port 1053 as udp serving port");
    let udp_serve = UdpSocket::bind("0.0.0.0:1053").await.unwrap();
    let forward = UdpSocket::bind("0.0.0.0:1054").await.unwrap();

    let udp_server = Arc::new(UdpService::new(udp_serve, forward));

    // tasks received from downstream
    let (task_sender, task_recv) = mpsc::unbounded_channel();

    // recursive lookup
    let (rec_sender, rec_recv) = mpsc::unbounded_channel();

    // init cache
    tracing::info!("initialize cache with size: {}", CACHE_SIZE);
    let cache = DnsCache::new(CACHE_SIZE as u64, rec_sender);

    // deprecated udp forward service
    // tracing::info!("init UDP forwarding...");
    // let udp_forwarding = tokio::spawn(async move {
    // tracing::info!("initiated forwarder");
    // forwarder.run_forward(rec_recv).await
    // });

    tracing::info!("init UDP serving...");
    let udp_task_sender = task_sender.clone();
    let udp_serving = tokio::spawn(async move {
        tracing::info!("initiated udp server");
        udp_server.clone().run_udp(udp_task_sender).await
    });

    tracing::info!("binding port 1053 as tcp serving port");
    let tcp_serve = TcpListener::bind("0.0.0.0:1053").await.unwrap();
    let tcp_server = TcpService::new(tcp_serve, task_sender.clone(), CACHE_SIZE);
    tracing::info!("init TCP serving...");
    let tcp_serving = tokio::spawn(async move {
        tracing::info!("initiated tcp server");
        tcp_server.run().await
    });

    tracing::info!("binding port 1853 as tls serving port");
    let tls_underlay = TcpListener::bind("0.0.0.0:1853").await.unwrap();
    let tls_serve = TlsListener::new(tls_underlay, serv_config.clone());
    let tls_server = TlsService::new(tls_serve, task_sender.clone(), CACHE_SIZE);
    let tls_serving = tokio::spawn(async move {
        tracing::info!("initiated tls server");
        tls_server.run().await
    });

    tracing::info!("binding port 1853 as quic serving port");
    let quic_serv = SocketAddr::new(IpAddr::from(Ipv4Addr::UNSPECIFIED), 1853);
    let quic_config = quinn::ServerConfig::with_crypto(serv_config);
    let (endpoint, incoming) = quinn::Endpoint::server(quic_config.clone(), quic_serv).unwrap();
    let quic_server = QuicService::new(incoming, task_sender);
    let quic_serving = tokio::spawn(async move {
        tracing::info!(
            "starting service on: quic://{}",
            endpoint.local_addr().unwrap()
        );
        quic_server.run().await
    });

    tracing::info!("binding port 1854 as quic forwarding port");
    let forward = SocketAddr::new(IpAddr::from(Ipv6Addr::UNSPECIFIED), 1854);
    let quic_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut endpoint = quinn::Endpoint::client(forward).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_config)));
    let forwarder = QuicForwarder::try_new(rec_recv, endpoint, upstream_domain, upstream_addr)
        .await
        .unwrap();
    tracing::info!("init forward");
    let forwarding = tokio::spawn(forwarder.run());

    tracing::info!("init transaction");
    let transaction = tokio::spawn(async move {
        transaction(task_recv, cache).await;
    });

    let (f, s, do_tcp, do_tls, do_quic, t) = tokio::join!(
        forwarding,
        udp_serving,
        tcp_serving,
        tls_serving,
        quic_serving,
        transaction
    );
    f.unwrap().unwrap();
    s.unwrap().unwrap();
    do_tcp.unwrap();
    do_quic.unwrap();
    do_tls.unwrap();
    t.unwrap();
    tracing::info!("quit service");
}
