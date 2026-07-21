use bio_loop::digest::{Digestor, HYSTERESIS_HIGH};
use bio_loop::{create_membrane, Event};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicBool, Arc};

fn prepare_events(tx: &crossbeam_channel::Sender<Event>, count: usize) {
    for _ in 0..count {
        let _ = tx.try_send(Event::Data([0xAB; 63]));
    }
}

fn bench_digest_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("digest/throughput");
    group.sample_size(30);

    for &fill in &[64, 256, 512] {
        group.throughput(Throughput::Elements(fill as u64));
        group.bench_function(format!("{}_events", fill), |b| {
            b.iter_batched(
                || {
                    let running = Arc::new(AtomicBool::new(true));
                    let (tx, rx) = create_membrane();
                    let digestor = Digestor::new(rx, Arc::clone(&running));
                    prepare_events(&tx, fill);
                    let _ = tx.send(Event::Shutdown);
                    (digestor, running)
                },
                |(mut digestor, _running)| {
                    digestor.run();
                    let processed = digestor.metrics.processed.load(Ordering::Relaxed);
                    black_box(processed);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_digest_under_backpressure(c: &mut Criterion) {
    let mut group = c.benchmark_group("digest/backpressure");
    group.sample_size(20);

    let overflow = HYSTERESIS_HIGH + 128;
    group.throughput(Throughput::Elements(overflow as u64));
    group.bench_function("overflow_triggered", |b| {
        b.iter_batched(
            || {
                let running = Arc::new(AtomicBool::new(true));
                let (tx, rx) = create_membrane();
                let digestor = Digestor::new(rx, Arc::clone(&running));
                prepare_events(&tx, overflow);
                let _ = tx.send(Event::Shutdown);
                (digestor, running)
            },
            |(mut digestor, _running)| {
                digestor.run();
                let (processed, dropped, suppressions) = digestor.metrics.snapshot();
                black_box((processed, dropped, suppressions));
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_digest_latency_consistency(c: &mut Criterion) {
    let mut group = c.benchmark_group("digest/latency");
    group.sample_size(50);

    group.bench_function("per_event", |b| {
        b.iter_batched(
            || {
                let running = Arc::new(AtomicBool::new(true));
                let (tx, rx) = create_membrane();
                let digestor = Digestor::new(rx, Arc::clone(&running));
                let _ = tx.send(Event::Data([0x42; 63]));
                let _ = tx.send(Event::Shutdown);
                (digestor, running)
            },
            |(mut digestor, _running)| {
                digestor.run();
                black_box(digestor.metrics.processed.load(Ordering::Relaxed));
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_digest_throughput,
    bench_digest_under_backpressure,
    bench_digest_latency_consistency,
);
criterion_main!(benches);
