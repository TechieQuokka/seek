use criterion::{black_box, criterion_group, criterion_main, Criterion};
use seek::engine::detection::signature_scanner::SignatureScanner;
use seek::engine::filesystem::file_analyzer::FileAnalyzer;
use std::path::Path;
use tempfile::NamedTempFile;
use std::io::Write;

fn benchmark_signature_scanner(c: &mut Criterion) {
    let scanner = SignatureScanner::new();

    // Create test file
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "Test file content for benchmarking").unwrap();

    let analyzer = FileAnalyzer::new();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let analysis = rt.block_on(async {
        analyzer.analyze_file(temp_file.path()).await.unwrap()
    });

    c.bench_function("signature_scan_file", |b| {
        b.to_async(&rt).iter(|| async {
            scanner.scan_file(black_box(temp_file.path()), black_box(&analysis)).await
        })
    });
}

fn benchmark_file_analyzer(c: &mut Criterion) {
    let analyzer = FileAnalyzer::new();

    // Create test files of different sizes
    let small_file = create_test_file(1024); // 1KB
    let medium_file = create_test_file(1024 * 1024); // 1MB
    let large_file = create_test_file(10 * 1024 * 1024); // 10MB

    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("analyze_small_file", |b| {
        b.to_async(&rt).iter(|| async {
            analyzer.analyze_file(black_box(small_file.path())).await
        })
    });

    c.bench_function("analyze_medium_file", |b| {
        b.to_async(&rt).iter(|| async {
            analyzer.analyze_file(black_box(medium_file.path())).await
        })
    });

    c.bench_function("analyze_large_file", |b| {
        b.to_async(&rt).iter(|| async {
            analyzer.analyze_file(black_box(large_file.path())).await
        })
    });
}

fn benchmark_entropy_calculation(c: &mut Criterion) {
    let analyzer = FileAnalyzer::new();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Create files with different entropy levels
    let low_entropy_file = create_test_file_with_content(vec![0u8; 10000]); // Low entropy
    let high_entropy_file = create_random_file(10000); // High entropy

    c.bench_function("entropy_low_entropy_file", |b| {
        b.to_async(&rt).iter(|| async {
            analyzer.analyze_file(black_box(low_entropy_file.path())).await
        })
    });

    c.bench_function("entropy_high_entropy_file", |b| {
        b.to_async(&rt).iter(|| async {
            analyzer.analyze_file(black_box(high_entropy_file.path())).await
        })
    });
}

fn create_test_file(size: usize) -> NamedTempFile {
    let mut temp_file = NamedTempFile::new().unwrap();
    let content = "A".repeat(size);
    temp_file.write_all(content.as_bytes()).unwrap();
    temp_file
}

fn create_test_file_with_content(content: Vec<u8>) -> NamedTempFile {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&content).unwrap();
    temp_file
}

fn create_random_file(size: usize) -> NamedTempFile {
    use rand::Rng;
    let mut temp_file = NamedTempFile::new().unwrap();
    let mut rng = rand::thread_rng();
    let content: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
    temp_file.write_all(&content).unwrap();
    temp_file
}

criterion_group!(
    benches,
    benchmark_signature_scanner,
    benchmark_file_analyzer,
    benchmark_entropy_calculation
);
criterion_main!(benches);