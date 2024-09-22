use edrivers::process::maps::parse_mapping;

#[test]
fn test_parse_mapping() {
    if let Ok(e) = parse_mapping(1) {
        assert_ne!(e.len(), 0);
    } else {
        panic!("parse mapping failed");
    }
}
