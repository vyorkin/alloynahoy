use std::error::Error;
use std::ops::{Add, Div, Mul, Sub};

use alloy::network::TransactionBuilder;
use alloy::primitives::utils::{format_units, parse_units};
use alloy::primitives::{B256, Bytes, keccak256};
use alloy::providers::ProviderBuilder;
use alloy::providers::{Provider, ext::AnvilApi};
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::{SolCall, SolValue};
use alloy::{hex, sol};
use alloy::{
    primitives::{Address, U256, address},
    uint,
};

pub static WETH_ADDR: Address = address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
pub static DAI_ADDR: Address = address!("6B175474E89094C44Da98b954EedeAC495271d0F");

sol! {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

sol!(
    #[sol(rpc)]
    contract IERC20 {
        function balanceOf(address target) returns (uint256);
    }
);

sol!(
    #[sol(rpc)]
    FlashBotsMultiCall,
    "../../sol/out/BundleExecutor.sol/FlashBotsMultiCall.json"
);

#[derive(Debug)]
pub struct UniV2Pair {
    pub address: Address,
    pub token0: Address,
    pub token1: Address,
    pub reserve0: U256,
    pub reserve1: U256,
}

pub fn get_uniswap_pair() -> UniV2Pair {
    UniV2Pair {
        address: address!("A478c2975Ab1Ea89e8196811F51A7B7Ade33eB11"),
        token0: DAI_ADDR,
        token1: WETH_ADDR,
        reserve0: uint!(6227630995751221000110015_U256),
        reserve1: uint!(2634810784674972449382_U256),
    }
}

pub fn get_sushi_pair() -> UniV2Pair {
    UniV2Pair {
        address: address!("C3D03e4F041Fd4cD388c549Ee2A29a9E5075882f"),
        token0: DAI_ADDR,
        token1: WETH_ADDR,
        reserve0: uint!(4314397529132715691120541_U256),
        reserve1: uint!(1845242683965617816423_U256),
    }
}

pub fn get_amount_out(reserve_in: U256, reserve_out: U256, amount_in: U256) -> U256 {
    let amount_in_with_fee = amount_in * get_uniswappy_fee();
    let numerator = amount_in_with_fee * reserve_out;
    let denominator = reserve_in * U256::from(1000) + amount_in_with_fee;
    numerator / denominator
}

pub fn get_amount_in(
    reserves00: U256,
    reserves01: U256,
    is_weth0: bool,
    reserves10: U256,
    reserves11: U256,
) -> U256 {
    let numerator = get_numerator(reserves00, reserves01, is_weth0, reserves10, reserves11);
    let denominator = get_denominator(reserves00, reserves01, is_weth0, reserves10, reserves11);

    numerator * U256::from(1000) / denominator
}

fn sqrt(input: U256) -> U256 {
    if input == U256::ZERO {
        return U256::ZERO;
    }

    let mut z = (input + U256::from(1)) / U256::from(2);
    let mut y = input;
    while z < y {
        y = z;
        z = (input / z + z) / U256::from(2);
    }
    y
}

fn get_numerator(
    reserves00: U256,
    reserves01: U256,
    is_weth0: bool,
    reserves10: U256,
    reserves11: U256,
) -> U256 {
    if is_weth0 {
        let presqrt = get_uniswappy_fee()
            .mul(get_uniswappy_fee())
            .mul(reserves01)
            .mul(reserves10)
            .div(reserves11)
            .div(reserves00);
        sqrt(presqrt)
            .sub(U256::from(1000))
            .mul(reserves11)
            .mul(reserves00)
    } else {
        let presqrt = get_uniswappy_fee()
            .mul(get_uniswappy_fee())
            .mul(reserves00)
            .mul(reserves11)
            .div(reserves10)
            .div(reserves01);
        (sqrt(presqrt))
            .sub(U256::from(1000))
            .mul(reserves10)
            .mul(reserves01)
    }
}

fn get_denominator(
    reserves00: U256,
    reserves01: U256,
    is_weth0: bool,
    reserves10: U256,
    reserves11: U256,
) -> U256 {
    if is_weth0 {
        get_uniswappy_fee()
            .mul(reserves11)
            .mul(U256::from(1000))
            .add(get_uniswappy_fee().mul(get_uniswappy_fee()).mul(reserves01))
    } else {
        get_uniswappy_fee()
            .mul(reserves10)
            .mul(U256::from(1000))
            .add(get_uniswappy_fee().mul(get_uniswappy_fee()).mul(reserves00))
    }
}

fn get_uniswappy_fee() -> U256 {
    U256::from(997)
}

async fn set_hash_storage_slot<P: Provider>(
    anvil_provider: P,
    address: Address,
    hash_slot: U256,
    hash_key: Address,
    value: U256,
) -> eyre::Result<()> {
    let hashed_slot = keccak256((hash_key, hash_slot).abi_encode());

    anvil_provider
        .anvil_set_storage_at(address, hashed_slot.into(), value.into())
        .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let uniswap_pair = get_uniswap_pair();
    let sushi_pair = get_sushi_pair();

    let wallet_address = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    let provider = ProviderBuilder::new().connect_anvil_with_wallet_and_config(|anvil| {
        anvil.fork("https://reth-ethereum.ithaca.xyz/rpc")
    })?;

    let executor = FlashBotsMultiCall::deploy(provider.clone(), wallet_address).await?;
    let iweth = IERC20::new(WETH_ADDR, provider.clone());

    set_hash_storage_slot(
        provider.clone(),
        WETH_ADDR,
        U256::from(3),
        *executor.address(),
        parse_units("5.0", "ether")?.into(),
    )
    .await?;

    provider
        .anvil_set_storage_at(
            uniswap_pair.address,
            U256::from(8), // getReserves slot
            B256::from_slice(&hex!(
                "665c6fcf00000000008ed55850d607f83a660000000526c08d812099d2577fbf"
            )),
        )
        .await?;

    set_hash_storage_slot(
        &provider,
        WETH_ADDR,
        U256::from(3),
        uniswap_pair.address,
        uniswap_pair.reserve1,
    )
    .await?;

    set_hash_storage_slot(
        &provider,
        DAI_ADDR,
        U256::from(2),
        uniswap_pair.address,
        uniswap_pair.reserve0,
    )
    .await?;

    provider
        .anvil_set_storage_at(
            sushi_pair.address,
            U256::from(8), // getReserves slot
            B256::from_slice(&hex!(
                "665c6fcf00000000006407e2ec8d4f09436700000003919bf56d886af022979d"
            )),
        )
        .await?;

    set_hash_storage_slot(
        &provider,
        WETH_ADDR,
        U256::from(3),
        sushi_pair.address,
        sushi_pair.reserve1,
    )
    .await?;

    set_hash_storage_slot(
        &provider,
        DAI_ADDR,
        U256::from(2),
        sushi_pair.address,
        sushi_pair.reserve0,
    )
    .await?;

    let balance_of = iweth.balanceOf(*executor.address()).call().await?;
    println!("Before - WETH balance of executor {:?}", balance_of);

    let weth_amount_in = get_amount_in(
        uniswap_pair.reserve0,
        uniswap_pair.reserve1,
        false,
        sushi_pair.reserve0,
        sushi_pair.reserve1,
    );

    let dai_amount_out =
        get_amount_out(uniswap_pair.reserve1, uniswap_pair.reserve0, weth_amount_in);

    let weth_amount_out = get_amount_out(sushi_pair.reserve0, sushi_pair.reserve1, dai_amount_out);

    let swap1 = swapCall {
        amount0Out: dai_amount_out,
        amount1Out: U256::ZERO,
        to: sushi_pair.address,
        data: Bytes::new(),
    }
    .abi_encode();

    let swap2 = swapCall {
        amount0Out: U256::ZERO,
        amount1Out: weth_amount_out,
        to: *executor.address(),
        data: Bytes::new(),
    }
    .abi_encode();

    let arb_calldata = FlashBotsMultiCall::uniswapWethCall {
        _wethAmountToFirstMarket: weth_amount_in,
        _ethAmountToCoinbase: U256::ZERO,
        _targets: vec![uniswap_pair.address, sushi_pair.address],
        _payloads: vec![Bytes::from(swap1), Bytes::from(swap2)],
    }
    .abi_encode();

    let arb_tx = TransactionRequest::default()
        .with_to(*executor.address())
        .with_input(arb_calldata);

    let pending = provider.send_transaction(arb_tx).await?;
    pending.get_receipt().await?;

    let balance_of = iweth.balanceOf(*executor.address()).call().await?;
    println!("After - WETH balance of executor {:?}", balance_of);

    Ok(())
}
