use alloy_primitives::{Address, Bytes, U256};
use revm::{
    db::{CacheDB, EmptyDB},
    primitives::{AccountInfo, ExecutionResult, Output, TransactTo},
    Evm,
};

/// Disable the contract size limit for deployments (test contracts can be large)
const DISABLE_CONTRACT_SIZE_LIMIT: bool = true;
use std::path::Path;

pub struct EvmRunner {
    db: CacheDB<EmptyDB>,
    caller: Address,
}

impl EvmRunner {
    pub fn new() -> Self {
        let mut db = CacheDB::new(EmptyDB::default());
        let caller = Address::repeat_byte(0x01);
        db.insert_account_info(caller, AccountInfo { balance: U256::MAX, ..Default::default() });
        Self { db, caller }
    }

    pub fn deploy(&mut self, project_root: &Path, contract_name: &str) -> Address {
        let bytecode = load_bytecode(self, project_root, contract_name);

        let result = {
            let mut evm = Evm::builder()
                .with_ref_db(&mut self.db)
                .modify_cfg_env(|cfg| {
                    cfg.limit_contract_code_size =
                        if DISABLE_CONTRACT_SIZE_LIMIT { Some(usize::MAX) } else { None };
                })
                .modify_tx_env(|tx| {
                    tx.caller = self.caller;
                    tx.transact_to = TransactTo::Create;
                    tx.data = Bytes::from(bytecode);
                    tx.value = U256::ZERO;
                    tx.gas_limit = 30_000_000;
                })
                .build();
            evm.transact_commit().unwrap()
        };

        match result {
            ExecutionResult::Success { output: Output::Create(_, Some(addr)), .. } => addr,
            other => panic!("deployment of {contract_name} failed: {other:?}"),
        }
    }

    fn deploy_raw(&mut self, bytecode: Vec<u8>) -> Address {
        let result = {
            let mut evm = Evm::builder()
                .with_ref_db(&mut self.db)
                .modify_cfg_env(|cfg| {
                    cfg.limit_contract_code_size =
                        if DISABLE_CONTRACT_SIZE_LIMIT { Some(usize::MAX) } else { None };
                })
                .modify_tx_env(|tx| {
                    tx.caller = self.caller;
                    tx.transact_to = TransactTo::Create;
                    tx.data = Bytes::from(bytecode);
                    tx.value = U256::ZERO;
                    tx.gas_limit = 30_000_000;
                })
                .build();
            evm.transact_commit().unwrap()
        };

        match result {
            ExecutionResult::Success { output: Output::Create(_, Some(addr)), .. } => addr,
            other => panic!("deployment of library failed: {other:?}"),
        }
    }

    pub fn call_raw(&mut self, to: Address, calldata: Vec<u8>) -> Vec<u8> {
        let result = {
            let mut evm = Evm::builder()
                .with_ref_db(&mut self.db)
                .modify_tx_env(|tx| {
                    tx.caller = self.caller;
                    tx.transact_to = TransactTo::Call(to);
                    tx.data = Bytes::from(calldata);
                    tx.value = U256::ZERO;
                    tx.gas_limit = 30_000_000;
                })
                .build();
            evm.transact_commit().unwrap()
        };

        match result {
            ExecutionResult::Success { output: Output::Call(data), .. } => data.to_vec(),
            other => panic!("call failed: {other:?}"),
        }
    }

    pub fn call_with_gas(&mut self, to: Address, calldata: Vec<u8>) -> (Vec<u8>, u64) {
        let result = {
            let mut evm = Evm::builder()
                .with_ref_db(&mut self.db)
                .modify_tx_env(|tx| {
                    tx.caller = self.caller;
                    tx.transact_to = TransactTo::Call(to);
                    tx.data = Bytes::from(calldata);
                    tx.value = U256::ZERO;
                    tx.gas_limit = 30_000_000;
                })
                .build();
            evm.transact_commit().unwrap()
        };

        match result {
            ExecutionResult::Success { output: Output::Call(data), gas_used, .. } =>
                (data.to_vec(), gas_used),
            other => panic!("call failed: {other:?}"),
        }
    }

    pub fn call_may_revert(&mut self, to: Address, calldata: Vec<u8>) -> Result<Vec<u8>, String> {
        let result = {
            let mut evm = Evm::builder()
                .with_ref_db(&mut self.db)
                .modify_tx_env(|tx| {
                    tx.caller = self.caller;
                    tx.transact_to = TransactTo::Call(to);
                    tx.data = Bytes::from(calldata);
                    tx.value = U256::ZERO;
                    tx.gas_limit = 30_000_000;
                })
                .build();
            evm.transact_commit().unwrap()
        };

        match result {
            ExecutionResult::Success { output: Output::Call(data), .. } => Ok(data.to_vec()),
            ExecutionResult::Revert { output, .. } => Err(format!("reverted: {}", output)),
            other => Err(format!("failed: {other:?}")),
        }
    }
}

/// Load bytecode from a foundry artifact, deploying and linking any libraries.
fn load_bytecode(runner: &mut EvmRunner, project_root: &Path, contract_name: &str) -> Vec<u8> {
    let out_dir = project_root.join("out");
    load_and_link_artifact(runner, &out_dir, contract_name)
}

/// Load and link a library, deploying any transitive library dependencies first.
fn load_and_link_artifact(runner: &mut EvmRunner, out_dir: &Path, artifact_name: &str) -> Vec<u8> {
    // Find the artifact
    for entry in std::fs::read_dir(out_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            let json_path = entry.path().join(format!("{artifact_name}.json"));
            if json_path.exists() {
                let content = std::fs::read_to_string(&json_path).unwrap();
                let artifact: serde_json::Value = serde_json::from_str(&content).unwrap();
                let mut bytecode_hex = artifact["bytecode"]["object"]
                    .as_str()
                    .expect("missing bytecode.object in artifact")
                    .to_string();

                // Recursively link any library dependencies
                if let Some(link_refs) = artifact["bytecode"]["linkReferences"].as_object() {
                    for (_source_file, libs) in link_refs {
                        for (lib_name, offsets) in libs.as_object().unwrap() {
                            // Recursively load and deploy the library
                            let lib_bytecode = load_and_link_artifact(runner, out_dir, lib_name);
                            let lib_addr = runner.deploy_raw(lib_bytecode);

                            let addr_hex = hex::encode(lib_addr.as_slice());

                            for offset_info in offsets.as_array().unwrap() {
                                let start = offset_info["start"].as_u64().unwrap() as usize;
                                let length = offset_info["length"].as_u64().unwrap() as usize;
                                assert_eq!(length, 20);

                                let hex_start = if bytecode_hex.starts_with("0x") {
                                    2 + start * 2
                                } else {
                                    start * 2
                                };
                                let hex_end = hex_start + length * 2;
                                bytecode_hex.replace_range(hex_start..hex_end, &addr_hex);
                            }
                        }
                    }
                }

                let hex_str = bytecode_hex.strip_prefix("0x").unwrap_or(&bytecode_hex);
                return hex::decode(hex_str).expect("invalid hex in bytecode after linking");
            }
        }
    }
    panic!("Artifact for '{artifact_name}' not found in {out_dir:?}");
}

/// Convenience: get the project root (parent of integration-tests/)
/// Get the project root (two levels up from tests/rust/)
pub fn project_root() -> std::path::PathBuf {
    std::env::current_dir()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
