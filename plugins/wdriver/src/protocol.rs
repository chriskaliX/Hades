use std::collections::HashMap;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Record {
    #[prost(int32, tag = "1")]
    pub data_type: i32,
    #[prost(int64, tag = "2")]
    pub timestamp: i64,
    #[prost(message, optional, tag = "3")]
    pub data: Option<Payload>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Payload {
    #[prost(map = "string, string", tag = "1")]
    pub fields: HashMap<String, String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Task {
    #[prost(int32, tag = "1")]
    pub data_type: i32,
    #[prost(string, tag = "2")]
    pub object_name: String,
    #[prost(string, tag = "3")]
    pub data: String,
    #[prost(string, tag = "4")]
    pub token: String,
}
