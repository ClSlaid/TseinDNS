use stretto::AsyncCache;
use tokio::time;

use crate::protocol::{Question, RRData, RR};

#[derive(Clone)]
pub struct DnsCache {
    cache: AsyncCache<Question, (RRData, time::Instant)>,
    coster: fn(&RRData) -> i64,
}

fn coster(rdata: &RRData) -> i64 {
    match rdata {
        RRData::A(_) => 5,
        RRData::Aaaa(_) => 1,
        RRData::Cname(_) => 1,
        RRData::Mx(_) => 1,
        RRData::Ns(_) => 2,
        RRData::Soa(_) => 5,
        RRData::Unknown(_) => 0,
    }
}

impl DnsCache {
    pub fn new(num_counters: usize, max_cost: i64) -> DnsCache {
        let cache = AsyncCache::new(num_counters, max_cost).unwrap();
        Self { cache, coster }
    }

    pub async fn append_rdata(&mut self, q: Question, data: RRData, ttl: u32) -> bool {
        let time = time::Duration::from_secs(ttl as u64);
        let cost = (self.coster)(&data);
        let ddl = time::Instant::now() + time;
        let data = (data, ddl);
        self.cache.insert_with_ttl(q, data, cost, time).await
    }

    pub async fn insert_rr(&mut self, q: Question, data: RR) -> bool {
        let ttl = data.get_ttl();
        let ddl = time::Instant::now() + ttl;
        let rdata = data.into_rdata();
        let cost = (self.coster)(&rdata);
        let data = (rdata, ddl);
        self.cache.insert_with_ttl(q, data, cost, ttl).await
    }

    pub async fn get(&self, q: Question) -> Option<(RRData, time::Instant)> {
        let val_ref = self.cache.get(&q);
        val_ref.as_ref()?;
        let val_ref = val_ref.unwrap();
        let data = (*val_ref.value()).clone();
        Some(data)
    }
}
