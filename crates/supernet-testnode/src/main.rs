//! `supernet-testnode [--listen 127.0.0.1:51820] [--state DIR]`
//!
//! Keeps its keys in DIR (default `local/testnode`) so the printed client
//! configuration stays valid across restarts.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use supernet_core::config::{decode_key, encode_key, NodeKind};
use supernet_core::wgconf;
use supernet_testnode::TestNode;

fn load_or_create_key(path: &std::path::Path) -> Result<[u8; 32]> {
    if path.exists() {
        return decode_key(&std::fs::read_to_string(path)?).with_context(|| format!("{}", path.display()));
    }
    let key = supernet_wg::generate_private_key();
    std::fs::write(path, encode_key(&key))?;
    Ok(key)
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut listen: SocketAddr = "127.0.0.1:51820".parse()?;
    let mut state = PathBuf::from("local/testnode");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next().context("--listen 需要地址")?.parse()?,
            "--state" => state = args.next().context("--state 需要目录")?.into(),
            "-h" | "--help" => {
                println!("supernet-testnode [--listen 127.0.0.1:51820] [--state DIR]");
                return Ok(());
            }
            other => bail!("未知参数 {other}"),
        }
    }
    std::fs::create_dir_all(&state)?;
    let server_key = load_or_create_key(&state.join("server.key"))?;
    let client_key = load_or_create_key(&state.join("client.key"))?;
    let node = TestNode::start(listen, server_key, client_key).await?;
    let client = node.client_node("测试节点");
    let NodeKind::Wireguard(wg) = &client.kind else { unreachable!("test node clients are WireGuard") };
    let conf = wgconf::render(wg);
    std::fs::write(state.join("client.conf"), &conf)?;
    println!("test node listening on udp {}", node.endpoint());
    println!("tunnel address {} (echo :7, http :80, dns :53)\n", supernet_testnode::NODE_IP);
    println!("{conf}");
    println!("link: {}", wgconf::to_link(&client));
    tokio::signal::ctrl_c().await?;
    Ok(())
}
