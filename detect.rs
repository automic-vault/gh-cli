use std::path::PathBuf;

pub fn install_is_insecure() -> Result<bool, String> {
    for path in gh_hosts_paths()? {
        if !path.exists() {
            continue;
        }
        let contents = std::fs::read_to_string(&path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        if contains_gh_auth_material(&contents) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn gh_hosts_paths() -> Result<Vec<PathBuf>, String> {
    if let Some(config_dir) = std::env::var_os("GH_CONFIG_DIR").filter(|value| !value.is_empty()) {
        return Ok(vec![PathBuf::from(config_dir).join("hosts.yml")]);
    }

    let mut paths = Vec::new();
    if let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty())
    {
        paths.push(PathBuf::from(config_home).join("gh/hosts.yml"));
    }

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    paths.push(home.join(".config/gh/hosts.yml"));
    Ok(paths)
}

fn contains_gh_auth_material(contents: &str) -> bool {
    contents.lines().any(|line| {
        let trimmed = line.trim();
        let Some((key, value)) = trimmed.split_once(':') else {
            return false;
        };
        matches!(key.trim(), "oauth_token" | "user")
            && !value.trim().is_empty()
            && value.trim() != "null"
    })
}
