extern crate yaml_rust;
use napi_derive::napi;
use napi::threadsafe_function::ThreadsafeFunction;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    path::PathBuf,
    ptr::null,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use yaml_rust::{YamlEmitter, YamlLoader};

use crate::{util::log::init_log};

pub struct RuleImpl {
    // dns
    rule_dns: Vec<RuleDns>,

    // redirect
    rule_redirect: Vec<RuleRediRect>,

    // transport
    rule_transport: Vec<RuleTranSport>,

    // directory
    rule_directory: Vec<RuleDirectory>,

    // process
    rule_process: RuleProcess,

    // thread
    rule_thread: RuleThread,

    // register
    rule_register: Vec<RuleResgiter>,
}

impl RuleImpl {
    pub async fn init() -> bool {
        let path = get_path().unwrap();
        let debug = init_log(&path);
        if !debug {
        }

        // get cuurent exec path
        let current_path = std::env::current_dir()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        if current_path.is_empty() {
            log::error!("Get Rule DirPath Failuer.");
            return false;
        }

        // init dns rule
        let mut rule_dns : Vec<RuleDns> = vec![];
        {
            let mut _data: String = String::from("");
            let rule_path: String = current_path.clone() + "\\config\\networkRuleConfig.yaml";
            let b: bool = RuleImpl::get_dns_rule(rule_path, &mut _data, &mut rule_dns);
            if true == b {
                log::debug!("analyze dns rule success. {}", _data);
            } else {
                log::error!("get dns rule fails.");
            }
        }

        // init redirect rule
        let mut rule_redirect :Vec<RuleRediRect> = vec![];
        {
            let mut _data: String = String::from("");
            let rule_path: String = current_path.clone() + "\\config\\networkRuleConfig.yaml";
            let b: bool = RuleImpl::get_redirect_rule(rule_path, &mut _data, &mut rule_redirect);
            if true == b {
                log::debug!("analyze redirect rule success. {}", _data);
            } else {
                log::error!("get redirect rule fails.");
            }
        }

        // init transport rule
        let mut rule_transport:Vec<RuleTranSport> = vec![];
        {
            let mut _data: String = String::from("");
            let rule_path: String = current_path.clone() + "\\config\\networkRuleConfig.yaml";
            let b: bool = RuleImpl::get_transport_rule(rule_path, &mut _data, &mut rule_transport);
            if true == b {
                log::debug!("analyze transport rule success. {}", _data);
            } else {
                log::error!("get transport rule fails.");
            }
        }

        // init directory rule
        let mut rule_directory: Vec<RuleDirectory> = vec![];
        {
            let mut _data: String = String::from("");
            let rule_path: String = current_path.clone() + "\\config\\directoryRuleConfig.json";
            let b = RuleImpl::get_dirtecory_rule(rule_path, &mut _data, &mut rule_directory).is_ok();
            if true == b {
                log::debug!("analyze directory success. {}", _data);
            } else {
                log::error!("get directory rule fails.");
            }
        }

        // init process rule
        let mut rule_process = RuleProcess {
            rule_type: 0,
            process_name: "".to_string(),
        };
        {
            let mut _data: String = String::from("");
            let rule_path: String = current_path.clone() + "\\config\\processRuleConfig.json";
            let b: bool = RuleImpl::get_process_rule(rule_path, &mut _data, &mut rule_process).is_ok();
            if true == b {
                log::debug!("analyze transport success. {}", _data);
            } else {
                log::error!("get transport rule fails.");
            }
        }

        // init thread rule
        let mut rule_thread = RuleThread {
            process_name: "".to_string(),
        };
        {
            let mut _data: String = String::from("");
            let rule_path: String = current_path.clone() + "\\config\\threadRuleConfig.json";
            let b: bool = RuleImpl::get_thread_rule(rule_path, &mut _data, &mut rule_thread).is_ok();
            if true == b {
                log::debug!("analyze thread success. {}", _data);
            } else {
                log::error!("get thread rule fails.");
            }
        }

        // init register rule
        let mut rule_register: Vec<RuleResgiter> = vec![];
        {
            let mut _data: String = String::from("");
            let rule_path: String = current_path.clone() + "\\config\\registerRuleConfig_.json";
            let b: bool = RuleImpl::get_register_rule(rule_path, &mut _data, &mut rule_register).is_ok();
            if true == b {
                log::debug!("analyze register success. {}", _data);
            } else {
                log::error!("get register rule fails.");
            }
        }

        Self {
            rule_dns: rule_dns,
            rule_redirect: rule_redirect,
            rule_transport: rule_transport,
            rule_directory: rule_directory,
            rule_process: rule_process,
            rule_thread: rule_thread,
            rule_register: rule_register,
        };

        return true;
    }

    // Read json, yaml Data
    pub fn read_file_data(file_path: String, _data: &mut String) -> bool {
        if file_path.is_empty() || null() == _data {
            return false;
        }
        if !PathBuf::from(file_path.to_string()).exists() {
            log::error!("Checkout Yaml File exists failuer. {}", file_path);
            return false;
        }
        *_data = fs::read_to_string(file_path.to_string()).unwrap();
        return true;
    }

    // Analyze dns rule
    pub fn get_dns_rule(file_path: String, _data: &mut String,  rule_dns: &mut Vec<RuleDns>) -> bool {
        if file_path.is_empty() {
            return false;
        }

        RuleImpl::read_file_data(file_path, _data);
        if _data.is_empty() {
            return false;
        }

        let docs: Vec<yaml_rust::Yaml> = YamlLoader::load_from_str(_data).unwrap();

        // Multi document support, doc is a yaml::Yaml
        let doc: &yaml_rust::Yaml = &docs[0];

        // Debug support
        println!("{:?}", doc);

        // Index access for map & array
        // assert_eq!(doc["foo"][0].as_str().unwrap(), "list1");
        // assert_eq!(doc["bar"][1].as_f64().unwrap(), 2.0);

        // // Chained key/array access is checked and won't panic,
        // // return BadValue if they are not exist.
        // assert!(doc["INVALID_KEY"][100].is_badvalue());

        // // Dump the YAML object
        // let mut out_str = String::new();
        // {
        //     let mut emitter = YamlEmitter::new(&mut out_str);
        //     emitter.dump(doc).unwrap(); // dump the YAML object to a String
        // }
        // println!("{}", out_str);
        return true;
    }

    // Analyze Redirect rule
    pub fn get_redirect_rule(file_path: String, _data: &mut String, rule_redirect: &mut Vec<RuleRediRect>) -> bool {
        if file_path.is_empty() {
            return false;
        }

        RuleImpl::read_file_data(file_path, _data);
        if _data.is_empty() {
            return false;
        }

        let docs: Vec<yaml_rust::Yaml> = YamlLoader::load_from_str(_data).unwrap();

        // Multi document support, doc is a yaml::Yaml
        let doc: &yaml_rust::Yaml = &docs[0];

        // Debug support
        println!("{:?}", doc);
        return true;
    }

    // Analyze transport layer rule
    pub fn get_transport_rule(file_path: String, _data: &mut String, rule_transport: &mut Vec<RuleTranSport>) -> bool {
        if file_path.is_empty() {
            return false;
        }

        RuleImpl::read_file_data(file_path, _data);
        if _data.is_empty() {
            return false;
        }

        let docs: Vec<yaml_rust::Yaml> = YamlLoader::load_from_str(_data).unwrap();

        // Multi document support, doc is a yaml::Yaml
        let doc: &yaml_rust::Yaml = &docs[0];

        // Debug support
        println!("{:?}", doc);
        return true;
    }

    // Analyze directory rule
    pub fn get_dirtecory_rule(file_path: String, _data: &mut String, rule_diretcory: &mut Vec<RuleDirectory>) -> Result<(), napi::Error> {
        loop {
            if file_path.is_empty() {
                break;
            }
            RuleImpl::read_file_data(file_path, _data);
            if _data.is_empty() {
                break;
            }

            *rule_diretcory = serde_json::from_str(&_data)?;

            break;
        }

        Ok(())
    }

    // Analyze process rule
    pub fn get_process_rule(file_path: String, _data: &mut String, rule_process: &mut RuleProcess) -> Result<(), napi::Error> {
        loop {
            if file_path.is_empty() {
                break;
            }
            RuleImpl::read_file_data(file_path, _data);
            if _data.is_empty() {
                break;
            }

            *rule_process = serde_json::from_str(&_data)?;

            break;
        }

        Ok(())
    }

    // Analyze thread rule
    pub fn get_thread_rule(file_path: String, _data: &mut String, rule_thread: &mut RuleThread) -> Result<(), napi::Error> {
        loop {
            if file_path.is_empty() {
                break;
            }
            RuleImpl::read_file_data(file_path, _data);
            if _data.is_empty() {
                break;
            }

            *rule_thread = serde_json::from_str(&_data).unwrap();

            break;
        }

        Ok(())
    }

    // Analyze register rule
    pub fn get_register_rule(file_path: String, _data: &mut String, rule_register: &mut Vec<RuleResgiter>) -> Result<(), napi::Error> {
        loop {
            if file_path.is_empty() {
                break;
            }
            RuleImpl::read_file_data(file_path, _data);
            if _data.is_empty() {
                break;
            }

            *rule_register = serde_json::from_str(&_data).unwrap();

            break;
        }
        
        Ok(())
    }

}

pub fn get_path() -> Result<PathBuf, napi::Error> {
    let path = process_path::get_dylib_path();
    if let Some(p) = path {
        if let Some(parent) = p.parent() {
            return Ok(parent.to_path_buf());
        }
    }
    Err(napi::Error::from_reason("get dylib path error".to_string()))
}

#[derive(Serialize, Deserialize)]
pub struct RuleDns {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "address")]
    pub address: String,
    #[serde(rename = "protocol")]
    pub protocol: String,
    #[serde(rename = "action")]
    pub action: String,
}

#[derive(Serialize, Deserialize)]
pub struct RuleRediRect {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "address")]
    pub address: String,
    #[serde(rename = "protocol")]
    pub protocol: String,
    #[serde(rename = "action")]
    pub action: String,
}

#[derive(Serialize, Deserialize)]
pub struct RuleTranSport {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "address")]
    pub address: String,
    #[serde(rename = "protocol")]
    pub protocol: String,
    #[serde(rename = "action")]
    pub action: String,
}

#[derive(Serialize, Deserialize)]
pub struct RuleDirectory {
    #[serde(rename = "FileIORuleMod")]
    pub rule_type: u32,
    #[serde(rename = "processName")]
    pub process_name: String,
    #[serde(rename = "Directory")]
    pub directory_path: String,
}

#[derive(Serialize, Deserialize)]
pub struct RuleProcess {
    #[serde(rename = "processRuleMod")]
    pub rule_type: u32,
    #[serde(rename = "processName")]
    pub process_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct RuleThread {
    #[serde(rename = "InjectIpsProcessNameArray")]
    pub process_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct RuleResgiter {
    #[serde(rename = "registerRuleMod")]
    pub rule_type: u32,
    #[serde(rename = "processName")]
    pub process_name: String,
    #[serde(rename = "registerValuse")]
    pub register_key: String,
    #[serde(rename = "permissions")]
    pub register_permiss: String,
}

