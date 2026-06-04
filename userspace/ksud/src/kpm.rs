use anyhow::{Context, Result, bail};
use serde_json::json;

use crate::ksucalls;

fn parse_info_value<'a>(info: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}=");
    info.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or("")
}

pub fn load(path: &str, args: &str) -> Result<()> {
    match ksucalls::kpm_load(path, args) {
        Ok(()) => Ok(()),
        Err(err) if err.raw_os_error() == Some(libc::ENOEXEC) => {
            anyhow::bail!(
                "failed to load KPM from {path}: unresolved or incompatible kernel symbols; check dmesg for 'kpm: unknown symbol'"
            )
        }
        Err(err) => Err(err).with_context(|| format!("failed to load KPM from {path}")),
    }?;
    Ok(())
}

pub fn unload(name: &str) -> Result<()> {
    ksucalls::kpm_unload(name).with_context(|| format!("failed to unload KPM {name}"))?;
    Ok(())
}

pub fn control(name: &str, args: &str) -> Result<()> {
    let output = ksucalls::kpm_control(name, args)
        .with_context(|| format!("failed to control KPM {name}"))?;
    if !output.is_empty() {
        println!("{output}");
    }
    Ok(())
}

pub fn list() -> Result<()> {
    let names = ksucalls::kpm_list().context("failed to list loaded KPMs")?;
    let mut items = Vec::new();

    for name in names.lines().map(str::trim).filter(|name| !name.is_empty()) {
        let info = ksucalls::kpm_info(name).with_context(|| format!("failed to query KPM {name}"))?;
        items.push(json!({
            "name": parse_info_value(&info, "name"),
            "version": parse_info_value(&info, "version"),
            "license": parse_info_value(&info, "license"),
            "author": parse_info_value(&info, "author"),
            "description": parse_info_value(&info, "description"),
            "args": parse_info_value(&info, "args"),
        }));
    }

    println!("{}", serde_json::to_string(&items)?);
    Ok(())
}

pub fn validate_args(args: &[String]) -> Result<String> {
    if args.iter().any(|arg| arg.as_bytes().contains(&0)) {
        bail!("KPM arguments must not contain NUL bytes");
    }
    Ok(args.join(" "))
}
