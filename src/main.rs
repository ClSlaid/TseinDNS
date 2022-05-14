// TODO: refract into a clap application
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::time;
use tokio_rustls::rustls::{Certificate, PrivateKey};
use tracing::instrument;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

use tsein_dns::comm::{TlsListener, TlsService};
use tsein_dns::{
    cache::DnsCache,
    comm::{Answer, QuicService, Task, TcpService, UdpService},
    protocol::{RRClass, RR},
};

const ALI_DNS: &str = "223.5.5.5:53";

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

async fn transaction(
    mut tasks: mpsc::UnboundedReceiver<Task>,
    rec_sender: mpsc::UnboundedSender<Task>,
    cache: DnsCache,
) {
    tracing::info!("initiated transaction layer");

    while let Some(task) = tasks.recv().await {
        tracing::debug!("received task");

        let rec_sender = rec_sender.clone();
        match task {
            Task::Query(query, ans_sender) => {
                // looking up local cache
                tracing::trace!("looking up local cache for query: {}", query.get_name());

                if let Some((rdata, ddl)) = cache.get(query.clone()).await {
                    // check if cached record is on-dated
                    let now = time::Instant::now();
                    if ddl > now {
                        tracing::trace!(
                            "looked up cache for query successfully: `{}`, type: `{}`",
                            query.get_name(),
                            query.get_type()
                        );
                        // calculate ttl
                        let ttl = ddl.duration_since(now);
                        let rr = RR::new(query.get_name(), ttl, RRClass::Internet, rdata);
                        let ans = Answer::Answer(rr);
                        ans_sender.send(ans).unwrap();
                        continue;
                    }
                }

                tracing::info!(
                    "unable to lookup query locally: {}, forwarding...",
                    query.get_name()
                );
                let (rec_query_sender, mut rec_ans_recv) = mpsc::unbounded_channel();

                let mut forwarding_cache = cache.clone();
                tokio::spawn(async move {
                    rec_sender
                        .send(Task::Query(query.clone(), rec_query_sender))
                        .unwrap();
                    let mut cached = false;
                    while let Some(answer) = rec_ans_recv.recv().await {
                        tracing::trace!("Get answer from upstream: {:?}", answer);
                        // cache one answer only
                        if !cached {
                            tracing::trace!("caching answer from upstream");
                            match answer.clone() {
                                Answer::Error(_) => todo!(),
                                Answer::Answer(rr) => {
                                    forwarding_cache.insert_rr(query.clone(), rr).await;
                                }
                                Answer::NameServer(rr) => {
                                    forwarding_cache.insert_rr(query.clone(), rr).await;
                                }
                                Answer::Additional(rr) => {
                                    forwarding_cache.insert_rr(query.clone(), rr).await;
                                }
                            };
                            cached = true;
                        }
                        ans_sender.send(answer).unwrap();
                    }
                });
            }
        };
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

    run();
}

#[instrument]
#[tokio::main]
async fn run() {
    // init cache
    let cache = DnsCache::new(10 * CACHE_SIZE, (5 * CACHE_SIZE) as i64);

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

    tracing::info!("binding port 1054 as forwarding port");
    let forward = UdpSocket::bind("0.0.0.0:1054").await.unwrap();
    tracing::info!("Setting up {} as upstream", ALI_DNS);
    forward.connect(ALI_DNS).await.unwrap();

    let udp_server = Arc::new(UdpService::new(udp_serve, forward));
    let forwarder = udp_server.clone();
    let (task_sender, task_recv) = mpsc::unbounded_channel();
    let (rec_sender, rec_recv) = mpsc::unbounded_channel();

    tracing::info!("init UDP forwarding...");
    let udp_forwarding = tokio::spawn(async move {
        tracing::info!("initiated forwarder");
        forwarder.run_forward(rec_recv).await
    });

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

    tracing::info!("binding port 1953 as quic serving port");
    let quic_serv = SocketAddr::new(IpAddr::from(Ipv4Addr::UNSPECIFIED), 1953);
    let quic_config = quinn::ServerConfig::with_crypto(serv_config);
    let (endpoint, incoming) = quinn::Endpoint::server(quic_config, quic_serv).unwrap();
    let quic_server = QuicService::new(incoming, task_sender);
    let quic_serving = tokio::spawn(async move {
        tracing::info!(
            "starting service on: quic://{}",
            endpoint.local_addr().unwrap()
        );
        quic_server.run().await
    });

    tracing::info!("init transaction");
    let transaction = tokio::spawn(async move {
        transaction(task_recv, rec_sender, cache).await;
    });

    let (f, s, do_tcp, do_tls, do_quic, t) = tokio::join!(
        udp_forwarding,
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
