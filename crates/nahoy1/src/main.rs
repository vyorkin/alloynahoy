use std::error::Error;

use alloy::{
    network::TransactionBuilder,
    primitives::{Address, U256, address, utils::Unit},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};

// sending tx's

const ANVIL_SERVER_ADDR: &str = "127.0.0.1:8545";

const ALICE: Address = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const ALICE_PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const BOB: Address = address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
const CHARLIE: Address = address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let alice_signer: PrivateKeySigner = ALICE_PK.parse()?;

    let provider = ProviderBuilder::new()
        .wallet(alice_signer)
        .connect(ANVIL_SERVER_ADDR)
        .await?;

    let value = Unit::ETHER.wei().saturating_mul(U256::from(100));

    let tx = TransactionRequest::default().with_to(BOB).with_value(value);

    let pending_tx = provider.send_transaction(tx).await?;
    println!("pending tx {}...", pending_tx.tx_hash());

    let receipt = pending_tx.get_receipt().await?;

    println!(
        "tx included in block {}",
        receipt
            .block_number
            .expect("failed to get block number from tx receipt")
    );

    Ok(())
}
