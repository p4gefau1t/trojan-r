#![forbid(unsafe_code)]

use clap::{App, Arg};
use std::env;

mod error;
mod protocol;
mod proxy;

fn main() {
    let matches = App::new("trojan-r")
        .version("v0.0.1")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .required(true)
                .takes_value(true)
                .help(".toml config file name"),
        )
        .author("Developed by @p4gefau1t (Page Fault)")
        .about("An unidentifiable mechanism that helps you bypass GFW")
        .get_matches();
    let filename = matches.value_of("config").unwrap().to_string();
    if env::var("SMOL_THREADS").is_err() {
        let mut thread_count = num_cpus::get() * 4;
        if thread_count < 8 {
            thread_count = 8;
        }
        env::set_var("SMOL_THREADS", thread_count.to_string());
    }
    smol::block_on(async {
        if let Err(e) = proxy::launch_from_config_filename(filename).await {
            println!("failed to launch proxy: {}", e);
        }
    });
}
