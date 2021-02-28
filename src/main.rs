#![forbid(unsafe_code)]

use clap::{App, Arg};

mod error;
mod protocol;
mod proxy;

#[tokio::main]
async fn main() {
    let matches = App::new("trojan-r")
        .version("v0.1.0")
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
    if let Err(e) = proxy::launch_from_config_filename(filename).await {
        println!("failed to launch proxy: {}", e);
    }
}
