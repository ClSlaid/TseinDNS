use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::comm::stream::worker::{Message, Worker};
use crate::comm::Task;

#[async_trait]
pub trait Listener {
    type S: AsyncReadExt + AsyncWriteExt + Unpin + Send;
    // name of the protocol
    fn name(&self) -> &'static str;
    // get serving address and port
    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    // accept stream from listener
    async fn accept(&self) -> std::io::Result<(Self::S, SocketAddr)>;
}

pub struct Service<L>
    where
        L: Listener + Send + Sync,
{
    listener: L,
    task: mpsc::UnboundedSender<Task>,
    message: mpsc::UnboundedReceiver<Message>,
    bell: mpsc::UnboundedSender<Message>,
    pool: stretto::AsyncCache<SocketAddr, oneshot::Sender<()>>,
}

impl<L: 'static + Listener + Send + Sync> Service<L> {
    pub fn new(listener: L, task: mpsc::UnboundedSender<Task>, limit: usize) -> Self {
        let (bell, message) = mpsc::unbounded_channel::<Message>();
        let pool = stretto::AsyncCacheBuilder::new(10 * limit, limit as i64)
            .finalize()
            .unwrap();
        Self {
            listener,
            task,
            message,
            bell,
            pool,
        }
    }

    pub async fn update(&mut self) -> Option<Message> {
        self.message.recv().await
    }

    pub async fn serve<S: 'static>(&mut self, client: SocketAddr, stream: S)
        where
            S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let task_sender = self.task.clone();
        let (tx, rx) = oneshot::channel();
        let bell = self.bell.clone();
        self.pool.insert(client, tx, 1).await;
        let worker = Worker::new(client, stream, task_sender, bell, rx);
        tokio::spawn(async move { worker.run().await });
    }

    pub async fn run(self) {
        let listener = self.listener;
        let task = self.task.clone();
        let msg_sender = self.bell.clone();
        let pool = self.pool.clone();

        let protocol_name = listener.name();

        tracing::info!(
            "starting tcp service on: {}",
            listener.local_addr().unwrap()
        );
        let listening = tokio::spawn(async move {
            while let Ok((stream, client)) = listener.accept().await {
                tracing::info!("incoming connection from {}://{}", protocol_name, client);

                let task = task.clone();
                let msg_sender = msg_sender.clone();
                let handler = Worker::serve(stream, client, task, msg_sender);
                pool.insert_with_ttl(client, handler, 1, std::time::Duration::from_secs(120))
                    .await;
                tracing::debug!("worker for {}://{} started", protocol_name, client);
            }
        });
        let mut msg = self.message;
        let pool = self.pool.clone();

        tracing::info!("starting manage workers in {} service", protocol_name);
        let updating = tokio::spawn(async move {
            while let Some(messages) = msg.recv().await {
                match messages {
                    Message::Update(client) => {
                        tracing::debug!("worker for {}://{} updated", protocol_name, client);
                        pool.get(&client);
                    }
                    Message::ShutDown(client) => {
                        pool.remove(&client).await;
                        tracing::info!("worker for {}://{} shutdown", protocol_name, client);
                    }
                }
            }
        });
        let _ = tokio::join!(listening, updating);
    }
}
