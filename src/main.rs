use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time;
use tracing::instrument;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

use tsein_dns::{
    cache::DnsCache,
    comm::{Answer, Manager, Task},
    protocol::{RRClass, RR},
};

const ALI_DNS: &str = "223.5.5.5:53";

const CACHE_SIZE: usize = 9192;

#[instrument]
#[tokio::main]
async fn main() {
    // init logger
    let timer = fmt::time::SystemTime;
    tracing_subscriber::registry()
        .with(fmt::layer().with_timer(timer))
        .init();
    tracing::info!(
        "Starting {}, version {}, author {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_AUTHORS")
    );
    // init cache
    let cache = DnsCache::new(10 * CACHE_SIZE, (5 * CACHE_SIZE) as i64);

    tracing::info!("binding port 1053 as serving port");
    let serve = UdpSocket::bind("0.0.0.0:1053").await.unwrap();

    tracing::info!("binding port 1054 as forwarding port");
    let forward = UdpSocket::bind("0.0.0.0:1054").await.unwrap();
    tracing::info!("Setting up {} as upstream", ALI_DNS);
    forward.connect(ALI_DNS).await.unwrap();

    let server = Arc::new(Manager::new(serve, forward));
    let forwarder = server.clone();
    let (task_sender, mut task_recv) = mpsc::unbounded_channel();
    let (rec_sender, rec_recv) = mpsc::unbounded_channel();

    tracing::info!("init forwarding...");
    let forwarding = tokio::spawn(async move {
        tracing::info!("initiated forwarder");
        forwarder.run_forward(rec_recv).await
    });

    tracing::info!("init serving...");
    let serving = tokio::spawn(async move {
        tracing::info!("initiated server");
        server.clone().run_udp(task_sender).await
    });

    tracing::info!("init transaction");
    let transaction = tokio::spawn(async move {
        tracing::info!("initiated transaction layer");

        while let Some(task) = task_recv.recv().await {
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
    });

    let (f, s, t) = tokio::join!(forwarding, serving, transaction);
    f.unwrap().unwrap();
    s.unwrap().unwrap();
    t.unwrap();
    tracing::info!("quit service");
}
