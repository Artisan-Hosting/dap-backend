use std::{env, path::PathBuf};

use artisan_dap::runner::Runner;

#[test]
fn runner_normalizes_relative_plugin_root_and_python_bin() {
    let cwd = env::current_dir().expect("cwd should resolve");
    let runner = Runner::new(PathBuf::from("plugins"), PathBuf::from("venvs/shared/bin/python3"));

    assert_eq!(runner.plugin_root, cwd.join("plugins"));
    assert_eq!(runner.python_bin, cwd.join("venvs/shared/bin/python3"));
}
