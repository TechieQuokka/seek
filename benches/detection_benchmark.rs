use criterion::{black_box, criterion_group, criterion_main, Criterion};
use seek::engine::detection::signature_scanner::SignatureScanner;
use std::path::Path;

fn benchmark_pattern_matching(c: &mut Criterion) {
    let scanner = SignatureScanner::new();

    // Test data for pattern matching
    let test_content_clean = b"This is a clean file with normal content that should not trigger any signatures.";
    let test_content_suspicious = b"This file contains powershell -encodedcommand which might be suspicious.";
    let test_hex_content = &[0x4d, 0x5a, 0x90, 0x00]; // PE header

    c.bench_function("pattern_match_clean", |b| {
        b.iter(|| {
            scanner.check_pattern(black_box(test_content_clean), black_box("virus_signature"))
        })
    });

    c.bench_function("pattern_match_suspicious", |b| {
        b.iter(|| {
            scanner.check_pattern(black_box(test_content_suspicious), black_box("powershell.*-encodedcommand"))
        })
    });

    c.bench_function("pattern_match_hex", |b| {
        b.iter(|| {
            scanner.check_pattern(black_box(test_hex_content), black_box("hex:4d5a9000"))
        })
    });
}

fn benchmark_hash_lookup(c: &mut Criterion) {
    let scanner = SignatureScanner::new();
    let (hash_count, _) = scanner.get_signature_count();

    c.bench_function("signature_count_lookup", |b| {
        b.iter(|| {
            black_box(scanner.get_signature_count())
        })
    });
}

fn benchmark_regex_compilation(c: &mut Criterion) {
    let test_patterns = vec![
        "powershell.*-encodedcommand",
        "cmd\\.exe.*\\/c",
        "\\\\[a-zA-Z]\\$.*\\\\.*\\.exe",
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
    ];

    c.bench_function("regex_compilation", |b| {
        b.iter(|| {
            for pattern in &test_patterns {
                if let Ok(regex) = regex::Regex::new(pattern) {
                    black_box(regex);
                }
            }
        })
    });
}

criterion_group!(
    benches,
    benchmark_pattern_matching,
    benchmark_hash_lookup,
    benchmark_regex_compilation
);
criterion_main!(benches);