use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use epoch_mmr::provenance::{LeafProvenance, LeafSource, ProvenanceRegistry};
use epoch_mmr::Mmr;

fn leaf_hash(byte: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = byte;
    h
}

fn bench_btreemap_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("btreemap/insert");
    group.sample_size(20);

    for &size in &[10_000u64, 100_000, 1_000_000] {
        group.throughput(Throughput::Elements(size));
        group.bench_function(format!("{}_records", size), |b| {
            b.iter_batched(
                ProvenanceRegistry::new,
                |mut reg| {
                    for i in 0..size {
                        reg.record(LeafProvenance::new(i, LeafSource::BioLoopDigest, 0));
                    }
                    black_box(reg.len());
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_btreemap_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("btreemap/lookup");
    group.sample_size(30);

    for &size in &[10_000u64, 100_000, 1_000_000] {
        let reg = {
            let mut r = ProvenanceRegistry::new();
            for i in 0..size {
                r.record(LeafProvenance::new(i, LeafSource::BioLoopDigest, 0));
            }
            r
        };

        group.bench_function(format!("{}_first", size), |b| {
            b.iter(|| black_box(reg.get(0)));
        });
        group.bench_function(format!("{}_mid", size), |b| {
            b.iter(|| black_box(reg.get(size / 2)));
        });
        group.bench_function(format!("{}_last", size), |b| {
            b.iter(|| black_box(reg.get(size - 1)));
        });
    }
    group.finish();
}

fn bench_mmr_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmr/append");
    group.sample_size(20);

    for &size in &[10_000u64, 100_000, 1_000_000] {
        group.throughput(Throughput::Elements(size));
        group.bench_function(format!("{}_leaves", size), |b| {
            b.iter_batched(
                Mmr::new,
                |mut mmr| {
                    for i in 0..size {
                        mmr.append(leaf_hash((i & 0xFF) as u8));
                    }
                    black_box(mmr.leaf_count);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_mmr_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmr/proof");
    group.sample_size(30);

    for &size in &[10_000u64, 100_000, 1_000_000] {
        let mmr = {
            let mut m = Mmr::new();
            for i in 0..size {
                m.append(leaf_hash((i & 0xFF) as u8));
            }
            m
        };

        group.bench_function(format!("{}_proof_first", size), |b| {
            b.iter(|| black_box(mmr.generate_proof(0)));
        });
        group.bench_function(format!("{}_proof_mid", size), |b| {
            b.iter(|| black_box(mmr.generate_proof(size / 2)));
        });
        group.bench_function(format!("{}_proof_last", size), |b| {
            b.iter(|| black_box(mmr.generate_proof(size - 1)));
        });
    }
    group.finish();
}

fn bench_mmr_seal(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmr/seal");
    group.sample_size(30);

    for &size in &[10_000u64, 100_000, 1_000_000] {
        let mut mmr = Mmr::new();
        for i in 0..size {
            mmr.append(leaf_hash((i & 0xFF) as u8));
        }

        group.bench_function(format!("{}_leaves", size), |b| {
            b.iter(|| black_box(mmr.seal_epoch().ok()));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_btreemap_insert,
    bench_btreemap_lookup,
    bench_mmr_append,
    bench_mmr_proof_generation,
    bench_mmr_seal,
);
criterion_main!(benches);
