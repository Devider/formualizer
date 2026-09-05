//! Standalone release probe: see benchmarks/perf-tranche-419-421.md.
//! The process-local allocator is isolated from the ordinary library test binary.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use std::time::Instant;

use formualizer_common::LiteralValue;
use formualizer_eval::engine::{Engine, EvalConfig, FormulaPlaneMode};
use formualizer_eval::test_workbook::TestWorkbook;
use formualizer_parse::parser::parse;

thread_local! {
    static ALLOCATIONS: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
}
struct ProbeAllocator;
#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

fn allocation(bytes: usize) {
    let _ = ALLOCATIONS.try_with(|c| {
        if let Some((calls, total)) = c.get() {
            c.set(Some((calls + 1, total + bytes)));
        }
    });
}
unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocation(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocation(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocation(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
}
fn measure(f: impl FnOnce()) -> (u128, usize, usize) {
    ALLOCATIONS.with(|c| c.set(Some((0, 0))));
    let start = Instant::now();
    f();
    let ns = start.elapsed().as_nanos();
    let (calls, bytes) = ALLOCATIONS.with(|c| c.replace(None).unwrap());
    (ns, calls, bytes)
}
fn config(mode: FormulaPlaneMode, threads: usize) -> EvalConfig {
    EvalConfig {
        enable_parallel: threads > 1,
        max_threads: Some(threads),
        formula_plane_mode: mode,
        arrow_storage_enabled: true,
        delta_overlay_enabled: true,
        write_formula_overlay_enabled: true,
        ..EvalConfig::default()
    }
}
fn formula(e: &mut Engine<TestWorkbook>, row: u32, col: u32, text: &str) {
    e.set_cell_formula("Sheet1", row, col, parse(text).unwrap())
        .unwrap();
}
fn dirty(e: &mut Engine<TestWorkbook>) {
    e.mark_all_formulas_dirty_for_test();
}
fn assert_number(e: &Engine<TestWorkbook>, row: u32, col: u32, expected: f64) {
    let v = e.get_cell_value("Sheet1", row, col).unwrap();
    let n = match v {
        LiteralValue::Number(n) => n,
        LiteralValue::Int(n) => n as f64,
        _ => panic!("{v:?}"),
    };
    assert_eq!(n, expected);
}
fn samples() -> usize {
    std::env::var("FZ_PERF_SAMPLES")
        .ok()
        .map(|s| s.parse().unwrap())
        .unwrap_or(7)
}

fn criteria() {
    const N: usize = 32768;
    for chunks in [1, 8, 32] {
        for predicates in [1, 4] {
            for text in [false, true] {
                for formulas in [1, 16] {
                    let mut e = Engine::new(TestWorkbook::new(), config(FormulaPlaneMode::Off, 1));
                    let setup = measure(|| {
                        let mut ingest = e.begin_bulk_ingest_arrow();
                        ingest.add_sheet("Sheet1", 2, N / chunks);
                        for i in 0..N {
                            let key = if text {
                                LiteralValue::Text(if i % 2 == 0 { "alpha" } else { "beta" }.into())
                            } else {
                                LiteralValue::Number((i % 2) as f64)
                            };
                            ingest
                                .append_row("Sheet1", &[key, LiteralValue::Number(2.0)])
                                .unwrap();
                        }
                        ingest.finish().unwrap();
                        let pred = if text { "\"alpha\"" } else { "\">0\"" };
                        let pairs = std::iter::repeat_n(format!("A1:A{N},{pred}"), predicates)
                            .collect::<Vec<_>>()
                            .join(",");
                        for row in 1..=formulas {
                            formula(&mut e, row, 4, &format!("=SUMIFS(B1:B{N},{pairs})"));
                        }
                    });
                    println!(
                        "criteria_setup chunks={chunks} p={predicates} text={text} formulas={formulas} ns={} allocs={} allocated_bytes={}",
                        setup.0, setup.1, setup.2
                    );
                    for sample in 0..samples() {
                        dirty(&mut e);
                        Engine::<TestWorkbook>::take_criteria_mask_work_for_test();
                        let m = measure(|| {
                            e.evaluate_all().unwrap();
                        });
                        let work = Engine::<TestWorkbook>::take_criteria_mask_work_for_test();
                        for row in 1..=formulas {
                            assert_number(&e, row, 4, N as f64);
                        }
                        println!(
                            "criteria chunks={chunks} p={predicates} text={text} formulas={formulas} sample={sample} ns={} allocs={} allocated_bytes={} mask_calls={} mask_logical_rows={}",
                            m.0, m.1, m.2, work.0, work.1
                        );
                    }
                    let edit = measure(|| {
                        e.set_cell_value("Sheet1", 1, 2, LiteralValue::Number(4.0))
                            .unwrap();
                    });
                    let recalc = measure(|| {
                        e.evaluate_all().unwrap();
                    });
                    for row in 1..=formulas {
                        assert_number(&e, row, 4, N as f64 + if text { 2.0 } else { 0.0 });
                    }
                    println!(
                        "criteria_edit chunks={chunks} p={predicates} text={text} formulas={formulas} edit_ns={} recalc_ns={} allocated_bytes={}",
                        edit.0, recalc.0, recalc.2
                    );
                }
            }
        }
    }
}

fn criteria_floors() {
    for whole_column in [false, true] {
        let mut e = Engine::new(TestWorkbook::new(), config(FormulaPlaneMode::Off, 1));
        let setup = measure(|| {
            let mut ingest = e.begin_bulk_ingest_arrow();
            ingest.add_sheet("Sheet1", 2, 2);
            for i in 0..8 {
                let value = if i == 0 || i == 7 {
                    LiteralValue::Number(1.0)
                } else {
                    LiteralValue::Empty
                };
                ingest
                    .append_row("Sheet1", &[value, LiteralValue::Number(2.0)])
                    .unwrap();
            }
            ingest.finish().unwrap();
            formula(
                &mut e,
                1,
                4,
                if whole_column {
                    "=SUMIFS(B:B,A:A,\">0\")"
                } else {
                    "=SUMIFS(B1:B8,A1:A8,\">0\")"
                },
            );
        });
        println!(
            "criteria_floor_setup whole_column={whole_column} ns={} allocated_bytes={}",
            setup.0, setup.2
        );
        for sample in 0..samples() {
            dirty(&mut e);
            Engine::<TestWorkbook>::take_criteria_mask_work_for_test();
            let m = measure(|| {
                e.evaluate_all().unwrap();
            });
            let work = Engine::<TestWorkbook>::take_criteria_mask_work_for_test();
            assert_number(&e, 1, 4, 4.0);
            println!(
                "criteria_floor whole_column={whole_column} sample={sample} ns={} allocs={} allocated_bytes={} mask_calls={} mask_logical_rows={}",
                m.0, m.1, m.2, work.0, work.1
            );
        }
    }
}

fn registry() {
    formualizer_eval::builtins::load_builtins();
    for threads in [1, 4] {
        for sample in 0..samples() {
            let start = Instant::now();
            let counts: Vec<_> = std::thread::scope(|s| {
                (0..threads)
                    .map(|_| {
                        s.spawn(|| {
                            measure(|| {
                                for _ in 0..100_000 {
                                    black_box(
                                        formualizer_eval::function_registry::get("", "ABS")
                                            .unwrap(),
                                    );
                                    black_box(
                                        formualizer_eval::function_registry::get("", "ROUND")
                                            .unwrap(),
                                    );
                                }
                            })
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|h| h.join().unwrap())
                    .collect()
            });
            println!(
                "registry threads={threads} sample={sample} ns={} lookups={} allocs={} allocated_bytes={}",
                start.elapsed().as_nanos(),
                threads * 200_000,
                counts.iter().map(|x| x.1).sum::<usize>(),
                counts.iter().map(|x| x.2).sum::<usize>()
            );
        }
        for mode in [
            FormulaPlaneMode::Off,
            FormulaPlaneMode::AuthoritativeExperimental,
        ] {
            for calls in [false, true] {
                let mut e = Engine::new(TestWorkbook::new(), config(mode, threads));
                let setup = measure(|| {
                    for row in 1..=2048 {
                        e.set_cell_value("Sheet1", row, 1, LiteralValue::Number(-2.0))
                            .unwrap();
                        let expr = if calls {
                            format!("=ABS(ROUND(ABS(ROUND(A{row},2)),2))")
                        } else {
                            format!("=((A{row}+2)*3-4)/2")
                        };
                        formula(&mut e, row, 2, &expr);
                    }
                });
                let spans = e.baseline_stats().formula_plane_active_span_count;
                assert_eq!(spans, 0);
                println!(
                    "registry_engine_setup threads={threads} mode={mode:?} calls={calls} ns={} active_spans={spans} execution=legacy",
                    setup.0
                );
                for sample in 0..samples() {
                    dirty(&mut e);
                    let m = measure(|| {
                        e.evaluate_all().unwrap();
                    });
                    for row in 1..=2048 {
                        assert_number(&e, row, 2, if calls { 2.0 } else { -2.0 });
                    }
                    println!(
                        "registry_engine threads={threads} mode={mode:?} calls={calls} formulas=2048 sample={sample} ns={} allocs_main_thread={} allocated_bytes_main_thread={}",
                        m.0, m.1, m.2
                    );
                }
            }
        }
    }
}

fn lookup() {
    const N: usize = 512;
    for mode in [
        FormulaPlaneMode::Off,
        FormulaPlaneMode::AuthoritativeExperimental,
    ] {
        for text in [false, true] {
            for axis_edit in [false, true] {
                for sample in 0..samples() {
                    let mut cfg = config(mode, 1);
                    cfg.lookup_index_cache_max_bytes = 512_000;
                    let mut e = Engine::new(TestWorkbook::new(), cfg);
                    let key = |i: usize| {
                        if text {
                            LiteralValue::Text(format!("key-{i:05}-{}", "x".repeat(96)))
                        } else {
                            LiteralValue::Number(i as f64)
                        }
                    };
                    let setup = measure(|| {
                        let mut ingest = e.begin_bulk_ingest_arrow();
                        ingest.add_sheet("Sheet1", 2, 64);
                        for i in 0..N {
                            ingest
                                .append_row("Sheet1", &[key(i), LiteralValue::Number(i as f64)])
                                .unwrap();
                        }
                        ingest.finish().unwrap();
                        e.set_cell_value("Sheet1", 1, 3, key(N - 1)).unwrap();
                        for row in 1..=24 {
                            let expr = match row % 3 {
                                0 => format!("=VLOOKUP($C$1,$A$1:$B${N},2,FALSE)"),
                                1 => format!("=MATCH($C$1,$A$1:$A${N},0)-1"),
                                _ => format!("=XLOOKUP($C$1,$A$1:$A${N},$B$1:$B${N})"),
                            };
                            formula(&mut e, row, 4, &expr);
                        }
                    });
                    let spans = e.baseline_stats().formula_plane_active_span_count;
                    assert_eq!(spans, 0);
                    println!(
                        "lookup_setup mode={mode:?} text={text} axis_edit={axis_edit} sample={sample} ns={} active_spans={spans} execution=legacy",
                        setup.0
                    );
                    for cycle in 0..16 {
                        let edit = measure(|| {
                            if cycle > 0 {
                                if axis_edit {
                                    let moved = cycle % 2 == 1;
                                    e.set_cell_value(
                                        "Sheet1",
                                        1,
                                        1,
                                        key(if moved { N - 1 } else { 0 }),
                                    )
                                    .unwrap();
                                    e.set_cell_value(
                                        "Sheet1",
                                        N as u32,
                                        1,
                                        key(if moved { 0 } else { N - 1 }),
                                    )
                                    .unwrap();
                                } else {
                                    e.set_cell_value(
                                        "Sheet1",
                                        1,
                                        6,
                                        LiteralValue::Number(cycle as f64),
                                    )
                                    .unwrap();
                                }
                            }
                        });
                        dirty(&mut e);
                        let m = measure(|| {
                            e.evaluate_all().unwrap();
                        });
                        let expected = if axis_edit && cycle % 2 == 1 {
                            0.0
                        } else {
                            (N - 1) as f64
                        };
                        for row in 1..=24 {
                            assert_number(&e, row, 4, expected);
                        }
                        println!(
                            "lookup mode={mode:?} text={text} axis_edit={axis_edit} sample={sample} cycle={cycle} edit_ns={} ns={} allocs={} allocated_bytes={} report={:?}",
                            edit.0,
                            m.0,
                            m.1,
                            m.2,
                            e.lookup_index_cache_report_for_test()
                        );
                        dirty(&mut e);
                        let warm = measure(|| {
                            e.evaluate_all().unwrap();
                        });
                        for row in 1..=24 {
                            assert_number(&e, row, 4, expected);
                        }
                        println!(
                            "lookup_warm mode={mode:?} text={text} axis_edit={axis_edit} sample={sample} cycle={cycle} ns={} allocs={} allocated_bytes={} report={:?}",
                            warm.0,
                            warm.1,
                            warm.2,
                            e.lookup_index_cache_report_for_test()
                        );
                    }
                }
            }
        }
    }
}

fn main() {
    match std::env::var("FZ_PERF_CASE").as_deref() {
        Ok("criteria") => {
            criteria();
            criteria_floors();
        }
        Ok("registry") => registry(),
        Ok("lookup") => lookup(),
        _ => {
            criteria();
            criteria_floors();
            registry();
            lookup();
        }
    }
}
