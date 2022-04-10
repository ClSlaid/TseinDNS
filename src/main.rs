use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::OnceCell;

use tsein_dns::comm::{Manager, Task};

static MANAGER: OnceCell<Manager> = OnceCell::const_new();

async fn get_manager(udp: UdpSocket, forward: UdpSocket) -> &'static Manager {
    MANAGER
        .get_or_init(|| async { Manager::new(udp, forward) })
        .await
}

#[tokio::main]
async fn main() {
    let serve = UdpSocket::bind("0.0.0.0:1053").await.unwrap();
    let forward = UdpSocket::bind("0.0.0.0:1054").await.unwrap();
    let manager = get_manager(serve, forward).await;
    let (task_sender, mut task_recv) = mpsc::channel(1);
    let (rec_sender, rec_recv) = mpsc::channel(1);
    let forwarding = tokio::spawn(async move { manager.run_forward(rec_recv).await });
    let serving = tokio::spawn(async move { manager.run_udp(task_sender).await });
    let transaction = tokio::spawn(async move {
        while let Some(task) = task_recv.recv().await {
            let rec_sender: mpsc::Sender<Task> = rec_sender.clone();
            match task {
                Task::Query(query, ans_sender) => {
                    // TODO: caching
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
}
