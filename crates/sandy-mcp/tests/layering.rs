//! AT-18: `sandy-mcp` never reaches `sandy-control-proto`, so the layering of
//! `docs/decisions/sandyd.md` section 7 is enforced by the build. Reads the
//! workspace `Cargo.lock` so it needs no cargo subprocess and runs in the
//! `nix flake check` test sandbox.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};

/// Package name -> dependency names (version suffix stripped), from `Cargo.lock`.
fn graph(lock: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut in_deps = false;
    for line in lock.lines() {
        if line == "[[package]]" {
            current = None;
            in_deps = false;
        } else if let Some(name) = line.strip_prefix("name = ") {
            let name = name.trim_matches('"').to_owned();
            out.entry(name.clone()).or_default();
            current = Some(name);
        } else if line.starts_with("dependencies = [") {
            in_deps = true;
        } else if in_deps && line == "]" {
            in_deps = false;
        } else if let (true, Some(pkg)) = (in_deps, &current) {
            let dep = line.trim().trim_matches(|c| c == ',' || c == '"');
            let name = dep.split(' ').next().unwrap_or(dep);
            out.entry(pkg.clone()).or_default().push(name.to_owned());
        }
    }
    out
}

fn reachable(g: &BTreeMap<String, Vec<String>>, from: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![from.to_owned()];
    while let Some(n) = stack.pop() {
        if seen.insert(n.clone()) {
            stack.extend(g.get(&n).into_iter().flatten().cloned());
        }
    }
    seen
}

#[test]
fn sandy_mcp_does_not_depend_on_sandy_control_proto() -> Result<()> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock");
    let lock = std::fs::read_to_string(path).context("read Cargo.lock")?;
    let g = graph(&lock);
    assert!(g.contains_key("sandy-mcp"), "sandy-mcp missing from Cargo.lock");
    // Guard the guard: the walker must see a known control-proto edge.
    assert!(
        reachable(&g, "sandyd").contains("sandy-control-proto"),
        "the lock walker cannot see sandyd -> sandy-control-proto"
    );
    let deps = reachable(&g, "sandy-mcp");
    assert!(
        !deps.contains("sandy-control-proto"),
        "sandy-mcp reaches sandy-control-proto (docs/decisions/sandyd.md section 7)"
    );
    Ok(())
}
