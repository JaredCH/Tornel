use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
pub struct PersonaView {
    pub id: String,
    pub name: String,
}

fn root(data_dir: &Path) -> PathBuf {
    std::env::var_os("ANON_PERSONA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.to_path_buf())
}

fn persona_dir(root: &Path, id: &str) -> Result<PathBuf, String> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid persona identifier".into());
    }
    Ok(root.join("personas").join(id))
}

fn list_at(root: &Path) -> Result<Vec<PersonaView>, String> {
    let path = root.join("personas");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut personas = Vec::new();
    for entry in std::fs::read_dir(path).map_err(|_| "could not list personas")? {
        let entry = entry.map_err(|_| "could not read persona entry")?;
        let id = entry.file_name().to_string_lossy().into_owned();
        if let Ok(dir) = persona_dir(root, &id) {
            let name_file = dir.join("name.json");
            if std::fs::metadata(&name_file)
                .map(|meta| meta.len() <= 1024)
                .unwrap_or(false)
            {
                let name: String = serde_json::from_slice(
                    &std::fs::read(name_file).map_err(|_| "could not read persona name")?,
                )
                .map_err(|_| "invalid persona name")?;
                personas.push(PersonaView { id, name });
            }
        }
    }
    personas.sort_by(|first, second| first.name.cmp(&second.name));
    Ok(personas)
}

fn create_at(root: &Path, name: &str) -> Result<PersonaView, String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err("persona name must contain 1 to 64 visible characters".into());
    }
    if list_at(root)?.len() >= 32 {
        return Err("persona limit reached".into());
    }
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "could not create persona identifier")?;
    let id: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    std::fs::create_dir_all(root.join("personas"))
        .map_err(|_| "could not create persona directory")?;
    let dir = persona_dir(root, &id)?;
    std::fs::create_dir(&dir).map_err(|_| "could not create persona")?;
    let encoded = serde_json::to_vec(name).map_err(|_| "invalid persona name")?;
    std::fs::write(dir.join("name.json"), encoded).map_err(|_| "could not save persona name")?;
    Ok(PersonaView {
        id,
        name: name.into(),
    })
}

pub fn list(data_dir: &Path) -> Result<Vec<PersonaView>, String> {
    list_at(&root(data_dir))
}

pub fn create(data_dir: &Path, name: &str) -> Result<PersonaView, String> {
    create_at(&root(data_dir), name)
}

fn launch_command(root: &Path, id: &str) -> Result<std::process::Command, String> {
    let dir = persona_dir(root, id)?
        .canonicalize()
        .map_err(|_| "persona not found")?;
    let managed = root
        .join("personas")
        .canonicalize()
        .map_err(|_| "persona directory not found")?;
    if !dir.starts_with(managed) {
        return Err("persona is outside its managed directory".into());
    }
    let persona = list_at(root)?
        .into_iter()
        .find(|persona| persona.id == id)
        .ok_or("persona not found")?;
    let mut command = std::process::Command::new(
        std::env::current_exe().map_err(|_| "could not locate application")?,
    );
    command
        .env("ANON_DATA_DIR", &dir)
        .env("ANON_PERSONA_ROOT", root)
        .env("ANON_WINDOW_TITLE", format!("anon - {}", persona.name))
        .env("WEBVIEW2_USER_DATA_FOLDER", dir.join("webview2"));
    Ok(command)
}

pub fn open(data_dir: &Path, id: &str) -> Result<(), String> {
    launch_command(&root(data_dir), id)?
        .spawn()
        .map_err(|_| "could not launch persona")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_personas_have_distinct_storage_and_launch_environments() {
        let root = std::env::temp_dir().join(format!(
            "anon-personas-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let alice = create_at(&root, "Personal").unwrap();
        let bob = create_at(&root, "Work").unwrap();
        assert_ne!(alice.id, bob.id);
        assert_eq!(list_at(&root).unwrap().len(), 2);
        assert!(persona_dir(&root, "../escape").is_err());
        assert!(create_at(&root, "\n").is_err());
        let alice_command = launch_command(&root, &alice.id).unwrap();
        let bob_command = launch_command(&root, &bob.id).unwrap();
        for variable in ["ANON_DATA_DIR", "WEBVIEW2_USER_DATA_FOLDER"] {
            let first = alice_command
                .get_envs()
                .find(|(key, _)| *key == variable)
                .unwrap()
                .1;
            let second = bob_command
                .get_envs()
                .find(|(key, _)| *key == variable)
                .unwrap()
                .1;
            assert_ne!(first, second);
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
