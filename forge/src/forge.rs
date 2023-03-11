use ethers::{
    abi::{Detokenize, Tokenize},
    solc::{Project, ProjectCompileOutput, ProjectPathsConfig},
    types::U256,
};
use forge::{
    executor::{
        inspector::CheatsConfig,
        opts::{Env, EvmOpts},
    },
    result::TestSetup,
    ContractRunner, MultiContractRunner, MultiContractRunnerBuilder,
};
use foundry_config::{fs_permissions::PathPermission, Config, FsPermissions};
use foundry_evm::executor::{Backend, EvmError, ExecutorBuilder};
use once_cell::sync::Lazy;
use std::{
    fmt::Debug,
    path::{Path, PathBuf},
};
use ethers::solc::remappings::Remapping;

static PROJECT: Lazy<Project> = Lazy::new(|| {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root = PathBuf::from(root.parent().unwrap().clone());
    let mut paths = ProjectPathsConfig::builder().root(root.clone()).build().unwrap();
    {
        // manually insert openzeppelin to remmapings. forge isn't autodetecting.
        root.push("lib/openzeppelin-contracts/contracts");
        paths.remappings.push(Remapping {
            name: "openzeppelin/".to_string(),
            path: root.to_str().unwrap().to_string(),
        });
    }
    Project::builder().paths(paths).ephemeral().no_artifacts().build().unwrap()
});

static EVM_OPTS: Lazy<EvmOpts> = Lazy::new(|| EvmOpts {
    env: Env {
        gas_limit: 18446744073709551615,
        chain_id: Some(foundry_common::DEV_CHAIN_ID),
        tx_origin: Config::DEFAULT_SENDER,
        block_number: 1,
        block_timestamp: 1,
        ..Default::default()
    },
    sender: Config::DEFAULT_SENDER,
    initial_balance: U256::MAX,
    ffi: true,
    memory_limit: 2u64.pow(24),
    ..Default::default()
});

static COMPILED: Lazy<ProjectCompileOutput> = Lazy::new(|| {
    let out = (*PROJECT).compile().unwrap();
    if out.has_compiler_errors() {
        eprintln!("{out}");
        panic!("Compiled with errors");
    }
    out
});

/// Builds a base runner
fn base_runner() -> MultiContractRunnerBuilder {
    MultiContractRunnerBuilder::default().sender(EVM_OPTS.sender)
}

fn manifest_root() -> PathBuf {
    let mut root = Path::new(env!("CARGO_MANIFEST_DIR"));
    // need to check here where we're executing the test from, if in `forge` we need to also allow
    // `testdata`
    if root.ends_with("forge") {
        root = root.parent().unwrap();
    }
    root.to_path_buf()
}

/// Builds a non-tracing runner
fn runner_with_config(mut config: Config) -> MultiContractRunner {
    config.allow_paths.push(manifest_root());

    base_runner()
        .with_cheats_config(CheatsConfig::new(&config, &EVM_OPTS))
        .sender(config.sender)
        .build(
            &PROJECT.paths.root,
            (*COMPILED).clone(),
            EVM_OPTS.evm_env_blocking().unwrap(),
            EVM_OPTS.clone(),
        )
        .unwrap()
}

/// Builds a non-tracing runner
pub fn runner() -> MultiContractRunner {
    let mut config = Config::with_root(PROJECT.root());
    config.fs_permissions = FsPermissions::new(vec![PathPermission::read_write(manifest_root())]);
    runner_with_config(config)
}

pub fn execute<T, R>(
    runner: &mut MultiContractRunner,
    contract_name: &'static str,
    fn_name: &'static str,
    args: T,
) -> Result<R, EvmError>
where
    T: Tokenize,
    R: Detokenize + Debug,
{
    let db = Backend::spawn(runner.fork.take());

    let names = runner.contracts.iter().map(|(id, _)| id.name.clone()).collect::<Vec<_>>();

    println!("names: {:?}", names);

    let (_, (abi, deploy_code, libs)) = runner
        .contracts
        .iter()
        .find(|(id, (abi, _, _))| id.name == contract_name && abi.functions.contains_key(fn_name))
        .unwrap();

    let function = abi.functions.get(fn_name).unwrap().first().unwrap().clone();

    let executor = ExecutorBuilder::default()
        .with_cheatcodes(runner.cheats_config.clone())
        .with_config(runner.env.clone())
        .with_spec(runner.evm_spec)
        .with_gas_limit(runner.evm_opts.gas_limit())
        .set_tracing(runner.evm_opts.verbosity >= 3)
        .set_coverage(runner.coverage)
        .build(db.clone());

    let mut single_runner = ContractRunner::new(
        executor,
        abi,
        deploy_code.clone(),
        runner.evm_opts.initial_balance,
        runner.sender,
        runner.errors.as_ref(),
        libs,
    );

    let setup = single_runner.setup(false).unwrap();
    let TestSetup { address, .. } = setup;

    let result = single_runner.executor.execute_test::<R, _, _>(
        single_runner.sender,
        address,
        function,
        args,
        0.into(),
        single_runner.errors,
    )?;

    println!("Gas used {fn_name}: {:#?}", result.gas_used);
    println!("Logs {fn_name}: {:#?}", result.logs);

    Ok(result.result)
}
