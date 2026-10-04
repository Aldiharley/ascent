// Wired into the pipeline in later tasks; until then the public API is only exercised by tests.
#[allow(dead_code)]
mod models;
#[allow(dead_code)]
mod normalise;
#[allow(dead_code)]
mod runner;
#[allow(dead_code)]
mod scope;
#[allow(dead_code)]
mod stages;

fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn main() {
    println!("ascent {}", version());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn has_version() {
        assert!(!version().is_empty());
    }
}
