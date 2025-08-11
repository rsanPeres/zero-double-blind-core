use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    system_instruction,
    transaction::Transaction,
    signature::Signer,
    pubkey::Pubkey,
};
use solana_sdk::signature::Keypair;

fn ensure_round_account_exists(
    rpc: &RpcClient,
    payer: &Keypair,
    round_pubkey: &Pubkey,
    round_seed: &str,
    program_id: &Pubkey,
    space: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if rpc.get_account(round_pubkey).is_ok() {
        return Ok(());
    }

    let lamports = rpc.get_minimum_balance_for_rent_exemption(space)?;
    let ix = system_instruction::create_account_with_seed(
        &payer.pubkey(),
        round_pubkey,
        &payer.pubkey(),
        round_seed,
        lamports,
        space as u64,
        program_id,
    );

    let bh = rpc.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[payer], bh);
    rpc.send_and_confirm_transaction(&tx)?;
    Ok(())
}
