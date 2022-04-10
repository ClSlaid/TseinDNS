use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::instrument;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

use tsein_dns::comm::{Manager, Task};

const ALI_DNS: &str = "223.5.5.5:53";

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

    tracing::info!("binding port 1053 as serving port");
    let serve = UdpSocket::bind("0.0.0.0:1053").await.unwrap();

    tracing::info!("binding port 1054 as forwarding port");
    let forward = UdpSocket::bind("0.0.0.0:1054").await.unwrap();
    tracing::info!("Setting up {} as upstream", ALI_DNS);
    forward.connect(ALI_DNS).await.unwrap();

    let server = Arc::new(Manager::new(serve, forward));
    let forwarder = server.clone();
    let (task_sender, mut task_recv) = mpsc::channel(1);
    let (rec_sender, rec_recv) = mpsc::channel(1);

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
            let rec_sender: mpsc::Sender<Task> = rec_sender.clone();
            match task {
                Task::Query(query, ans_sender) => {
                    // TODO: caching
                    tracing::info!(
                        "unable to lookup query locally: {}, forwarding...",
                        query.get_name()
                    );
                    let (rec_query_sender, mut rec_ans_recv) = mpsc::channel(1);
                    rec_sender
                        .send(Task::Query(query, rec_query_sender))
                        .await
                        .unwrap();
                    while let Some(answer) = rec_ans_recv.recv().await {
                        // TODO: caching
                        ans_sender.send(answer).await.unwrap();
                    }
                }
            };
        }
    });
    let v = tokio::join!(forwarding, serving, transaction);
    tracing::info!("quit service");
}
