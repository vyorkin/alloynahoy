use alloy::{
    primitives::{
        Address, U256, address,
        utils::{Unit, format_ether},
    },
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use std::error::Error;

// interacting with smart contracts

#[allow(dead_code)]
const NODE_ADDR: &str = "https://reth-ethereum.ithaca.xyz/rpc";
const LOCAL_NODE_ADDR: &str = "127.0.0.1:8545";

const ALICE_PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const WETH: Address = address!("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");

sol! {
    #[sol(rpc)]
    contract WETH9 {
        function deposit() public payable;
        function balanceOf(address) public view returns(uint256);
        function withdraw(uint256 amount) public;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let alice_signer: PrivateKeySigner = ALICE_PK.parse()?;
    let provider = ProviderBuilder::new()
        .wallet(alice_signer.clone())
        .connect(LOCAL_NODE_ADDR)
        .await?;
    // .connect_anvil_with_config(|anvil| anvil.fork(NODE_ADDR));

    let weth = WETH9::new(WETH, provider.clone());

    let from_address = alice_signer.address();
    let initial_balance = weth.balanceOf(from_address).call().await?;

    println!(
        "initial WETH balance: {} WETH",
        format_ether(initial_balance)
    );

    // deposit ETH to get WETH
    let deposit_amount = Unit::ETHER.wei().saturating_mul(U256::from(10));
    let deposit_tx = weth.deposit().value(deposit_amount).send().await?;
    let deposit_receipt = deposit_tx.get_receipt().await?;

    println!(
        "deposited ETH in block: {}",
        deposit_receipt
            .block_number
            .expect("failed to get block number")
    );

    let new_balance = weth.balanceOf(from_address).call().await?;
    println!("new WETH balance: {} WETH", format_ether(new_balance));

    // withdraw some WETH back to ETH
    let withdraw_amount = Unit::ETHER.wei().saturating_mul(U256::from(5));
    let withdraw_tx = weth.withdraw(withdraw_amount).send().await?;
    let withdraw_receipt = withdraw_tx.get_receipt().await?;

    println!(
        "withdrew ETH in block {}",
        withdraw_receipt
            .block_number
            .expect("failed to get block number")
    );

    let final_balance = weth.balanceOf(from_address).call().await?;
    println!("final WETH balance: {} WETH", format_ether(final_balance));

    Ok(())
}
