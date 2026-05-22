pub mod elasticsearch;
pub mod etcd;
pub mod memcache;
pub mod mongo;
pub mod mysql;
pub mod postgre;
pub mod prometheus;
pub mod redis;
pub mod sqlserver;

use crate::event::apps::IApp;

pub fn apps() -> Vec<Box<dyn IApp>> {
    vec![
        Box::new(mysql::Mysql::new()),
        Box::new(redis::Redis::new()),
        Box::new(postgre::PostgreSql::new()),
        Box::new(mongo::MongoDB::new()),
        Box::new(elasticsearch::ElasticSearch::new()),
        Box::new(etcd::Etcd::new()),
        Box::new(memcache::Memcache::new()),
        Box::new(prometheus::Prometheus::new()),
        Box::new(sqlserver::Sqlserver::new()),
    ]
}
