use super::*;
use nject::{injectable, module, provider};
use test::Bencher;

#[provider]
struct Provider;

#[injectable]
#[module]
struct Module(
    #[export] Dep1,
    #[export] Dep2,
    #[export] Dep3,
    #[export] Dep4,
    #[export] Dep5,
    #[export] Dep6,
    #[export] Dep7,
    #[export] Dep8,
    #[export] Dep9,
    #[export] Dep10,
);

#[injectable]
#[module]
struct ModuleDyn(
    #[export(dyn DepTrait1)] Dep1,
    #[export(dyn DepTrait2)] Dep2,
    #[export(dyn DepTrait3)] Dep3,
    #[export(dyn DepTrait4)] Dep4,
    #[export(dyn DepTrait5)] Dep5,
    #[export(dyn DepTrait6)] Dep6,
    #[export(dyn DepTrait7)] Dep7,
    #[export(dyn DepTrait8)] Dep8,
    #[export(dyn DepTrait9)] Dep9,
    #[export(dyn DepTrait10)] Dep10,
);

// #[injectable]
// #[module]
// struct ModuleImpl(
//     #[export(ImplDepTrait1)] Dep1,
//     #[export(ImplDepTrait2)] Dep2,
//     #[export(ImplDepTrait3)] Dep3,
//     #[export(ImplDepTrait4)] Dep4,
//     #[export(ImplDepTrait5)] Dep5,
//     #[export(ImplDepTrait6)] Dep6,
//     #[export(ImplDepTrait7)] Dep7,
//     #[export(ImplDepTrait8)] Dep8,
//     #[export(ImplDepTrait9)] Dep9,
//     #[export(ImplDepTrait10)] Dep10,
// );

#[injectable]
#[provider]
struct ModuleProvider(#[import] Module, #[import] ModuleDyn);

#[bench]
fn by_module_ref(b: &mut Bencher) {
    let provider = Provider.provide::<ModuleProvider>();
    b.iter(move || {
        for _ in 0..ITERATION_COUNT {
            test::black_box((
                provider.provide::<&Dep1>(),
                provider.provide::<&Dep2>(),
                provider.provide::<&Dep3>(),
                provider.provide::<&Dep4>(),
                provider.provide::<&Dep5>(),
                provider.provide::<&Dep6>(),
                provider.provide::<&Dep7>(),
                provider.provide::<&Dep8>(),
                provider.provide::<&Dep9>(),
                provider.provide::<&Dep10>(),
            ));
        }
    });
}

#[bench]
fn by_module_ref_dyn(b: &mut Bencher) {
    let provider = Provider.provide::<ModuleProvider>();
    b.iter(move || {
        for _ in 0..ITERATION_COUNT {
            test::black_box((
                provider.provide::<&dyn DepTrait1>(),
                provider.provide::<&dyn DepTrait2>(),
                provider.provide::<&dyn DepTrait3>(),
                provider.provide::<&dyn DepTrait4>(),
                provider.provide::<&dyn DepTrait5>(),
                provider.provide::<&dyn DepTrait6>(),
                provider.provide::<&dyn DepTrait7>(),
                provider.provide::<&dyn DepTrait8>(),
                provider.provide::<&dyn DepTrait9>(),
                provider.provide::<&dyn DepTrait10>(),
            ));
        }
    });
}
