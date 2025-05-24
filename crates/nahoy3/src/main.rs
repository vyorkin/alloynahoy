use alloy::{
    primitives::{Address, address, utils::format_ether},
    providers::{Provider, ProviderBuilder, WsConnect},
    sol,
};
use futures_util::StreamExt;
use std::error::Error;

// monitoring blockchain activity

const WS_NODE_ADDR: &str = "wss://reth-ethereum.ithaca.xyz/ws";

const UNISWAP_V3_POOL_ADDR: Address = address!("0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8");
const WETH_ADDR: Address = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");

sol! {
    #[sol(rpc)]
    contract WETH {
        function balanceOf(address) external view returns (uint256);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let ws = WsConnect::new(WS_NODE_ADDR);

    let provider = ProviderBuilder::new().connect_ws(ws).await?;
    let weth = WETH::new(WETH_ADDR, &provider);
    let mut block_stream = provider.subscribe_blocks().await?.into_stream();

    while let Some(block) = block_stream.next().await {
        println!("block #{}: {}", block.number, block.hash);
        let balance = weth
            .balanceOf(UNISWAP_V3_POOL_ADDR)
            .block(block.number.into())
            .call()
            .await?;

        println!(
            "UNISWAP-V3 WETH-USDC pool balance: {} WETH",
            format_ether(balance)
        );
    }

    Ok(())
}
