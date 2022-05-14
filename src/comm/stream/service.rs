// Copyright (c) 2022 ClSlaid <cailue@bupt.edu.cn>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot},
};

use crate::comm::{
    stream::worker::{Message, Worker},
    Task,
};

#[async_trait]
pub trait Listener {
    type R: AsyncReadExt + Unpin + Send;
    type W: AsyncWriteExt + Unpin + Send;
    // name of the protocol
    fn name(&self) -> &'static str;
    // get serving address and port
    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    // accept stream from listener
    async fn acquire(&mut self) -> std::io::Result<((Self::R, Self::W), SocketAddr)>;
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

    pub async fn serve<R: 'static, W: 'static>(
        &mut self,
        client: SocketAddr,
        read_stream: R,
        write_stream: W,
    ) where
        R: AsyncReadExt + Unpin + Send,
        W: AsyncWriteExt + Unpin + Send,
    {
        let stream = (read_stream, write_stream);
        let task_sender = self.task.clone();
        let (tx, rx) = oneshot::channel();
        let bell = self.bell.clone();
        self.pool.insert(client, tx, 1).await;
        let worker = Worker::new(client, stream, task_sender, bell, rx);
        tokio::spawn(async move { worker.run().await });
    }

    pub async fn run(self) {
        let mut listener = self.listener;
        let task = self.task.clone();
        let msg_sender = self.bell.clone();
        let pool = self.pool.clone();

        let protocol = listener.name();
        let server_addr = format!("{}://{}", protocol, listener.local_addr().unwrap());

        tracing::info!("starting service on: {}", server_addr);
        let listening = tokio::spawn(async move {
            while let Ok((stream, client)) = listener.acquire().await {
                let client_uri = format!("{}://{}", listener.name(), client);
                tracing::info!("incoming connection from {}", client_uri);

                let task = task.clone();
                let msg_sender = msg_sender.clone();
                let handler = Worker::serve(stream, client, task, msg_sender);
                pool.insert_with_ttl(client, handler, 1, std::time::Duration::from_secs(120))
                    .await;
                tracing::debug!("worker for {} started", client_uri);
            }
        });
        let mut msg = self.message;
        let pool = self.pool.clone();

        tracing::info!("starting manage workers in {} service", protocol);
        let updating = tokio::spawn(async move {
            while let Some(messages) = msg.recv().await {
                match messages {
                    Message::Update(client) => {
                        tracing::debug!("worker for {}://{} updated", protocol, client);
                        pool.get(&client);
                    }
                    Message::ShutDown(client) => {
                        pool.remove(&client).await;
                        tracing::info!("worker for {}://{} shutdown", protocol, client);
                    }
                }
            }
        });
        let _ = tokio::join!(listening, updating);
    }
}
