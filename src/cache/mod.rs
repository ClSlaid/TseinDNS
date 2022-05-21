// Copyright (c) 2022 ClSlaid <cailue@bupt.edu.cn>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::sync::Arc;

use async_recursion::async_recursion;
use moka::future::Cache;
use tokio::{sync::mpsc, time};

use crate::{
    comm::{Answer, Task},
    protocol::Question,
};
pub type Data = Vec<Answer>;
type RawCache = Cache<Question, (Data, time::Instant)>;

#[derive(Clone)]
pub struct DnsCache {
    cache: RawCache,
    rec: Arc<mpsc::UnboundedSender<Task>>,
}

impl DnsCache {
    pub fn new(capacity: u64, rec_sender: mpsc::UnboundedSender<Task>) -> DnsCache {
        let cache = RawCache::builder()
            .max_capacity(capacity)
            .time_to_live(time::Duration::from_secs(600))
            .build();
        let rec = Arc::new(rec_sender);
        Self { cache, rec }
    }

    // get will surely return a record, if it does exist
    // or it will return a None, then, just NXDOMAIN.
    #[async_recursion]
    pub async fn get(&mut self, q: Question) -> Vec<Answer> {
        let (got, ddl) = self
            .cache
            .get_with_if(
                q.clone(),
                forward(self.rec.clone(), q.clone()),
                |(_, ddl)| ddl <= &time::Instant::now(),
            )
            .await;
        let ttl = ddl - time::Instant::now();
        got.into_iter()
            .map(|rr| match rr {
                Answer::Error(e) => Answer::Error(e),
                Answer::Answer(mut a) => {
                    a.set_ttl(ttl);
                    Answer::Answer(a)
                }
                Answer::NameServer(mut ns) => {
                    ns.set_ttl(ttl);
                    Answer::NameServer(ns)
                }
                Answer::Additional(mut additional) => {
                    additional.set_ttl(ttl);
                    Answer::Additional(additional)
                }
            })
            .collect()
    }
}

async fn forward(rec: Arc<mpsc::UnboundedSender<Task>>, query: Question) -> (Data, time::Instant) {
    let name = query.get_name();
    tracing::debug!("start forwarding query: {}", name);
    let (ans_to, mut ans_from) = mpsc::unbounded_channel();
    let task = Task::Query(query, ans_to);
    let _ = rec.send(task);

    let mut min_ttl = time::Duration::from_secs(600);
    let mut answers = vec![];
    while let Some(ans) = ans_from.recv().await {
        match ans {
            Answer::Error(e) => {
                tracing::warn!("get error from upstream: {:?}", e);
                min_ttl = time::Duration::from_secs(600);
                answers.clear();
                answers.push(Answer::Error(e));
                break;
            }
            Answer::Answer(a) => {
                min_ttl = if min_ttl < a.get_ttl() {
                    min_ttl
                } else {
                    a.get_ttl()
                };
                answers.push(Answer::Answer(a));
            }
            Answer::NameServer(ns) => {
                min_ttl = if min_ttl < ns.get_ttl() {
                    min_ttl
                } else {
                    ns.get_ttl()
                };
                answers.push(Answer::NameServer(ns));
            }
            Answer::Additional(additional) => {
                min_ttl = if min_ttl < additional.get_ttl() {
                    min_ttl
                } else {
                    additional.get_ttl()
                };
                answers.push(Answer::Additional(additional));
            }
        }
    }
    tracing::info!(
        "Got {} RRs from upstream with minimum ttl: {}s",
        answers.len(),
        min_ttl.as_secs()
    );
    let ddl = time::Instant::now() + min_ttl;
    (answers, ddl)
}
