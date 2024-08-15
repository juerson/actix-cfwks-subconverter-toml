use rand::seq::SliceRandom;
use rand::thread_rng;

pub fn random_fingerprint() -> String {
    let fingerprint = vec![
        "chrome",
        "firefox",
        "safari",
        "edge",
        "random",
        "ios",
        "android",
        "random",
        "randomized",
    ];
    let client_fingerprint = fingerprint
        .choose(&mut thread_rng())
        .unwrap_or(&fingerprint[0])
        .to_string();
    client_fingerprint
}
