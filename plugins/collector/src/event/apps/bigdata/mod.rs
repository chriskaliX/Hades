pub mod activemq;
pub mod flink;
pub mod hadoop;
pub mod hbase;
pub mod kafka;
pub mod rabbitmq;
pub mod storm;
pub mod zookeeper;

use crate::event::apps::IApp;

pub fn apps() -> Vec<Box<dyn IApp>> {
    vec![
        Box::new(kafka::Kafka::new()),
        Box::new(zookeeper::Zookeeper::new()),
        Box::new(storm::Storm::new()),
        Box::new(flink::Flink::new()),
        Box::new(hadoop::Hadoop::new()),
        Box::new(hbase::Hbase::new()),
        Box::new(activemq::Activemq::new()),
        Box::new(rabbitmq::Rabbitmq::new()),
    ]
}
