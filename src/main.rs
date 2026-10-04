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
