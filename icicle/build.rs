fn main() {
    let files = [
        "native_hooks.c",
        "timer.c",
        "interrupt_triggers.c",
        "util.c",
        "state_snapshotting.c",
        "native_tracing.c",
        "uc_snapshot.c",
        "core_peripherals/cortexm_nvic.c",
        "core_peripherals/cortexm_systick.c",
    ];
    let base_path = std::path::Path::new("../harness/fuzzware_harness/native/");

    cc::Build::new()
        .include(&base_path)
        .files(files.iter().map(|file| base_path.join(file)))
        .debug(true)
        .warnings(false) // Fuzzware generates a lot of `unused-parameter` warning
        .compiler("clang")
        // .define("DEBUG_NVIC", "1")
        // .define("DEBUG_STATE_RESTORE", "1")
        // .define("DEBUG", "1")
        // .define("DEBUG_TIMER", "1")
        // .define("DEBUG_TIMER_TICK", "1")
        .compile("fuzzware-native");

    for file in files {
        println!("cargo:rerun-if-changed=./harness/fuzzware_harness/native/{file}");
    }

    let wrapper_header = "../harness/fuzzware_harness/native/wrapper.h";
    println!("cargo:rerun-if-changed={wrapper_header}");

    let bindings = bindgen::builder()
        .header(wrapper_header)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .size_t_is_usize(true)
        .layout_tests(false)
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .translate_enum_integer_types(true)
        .generate()
        .expect("failed to generated bindings");

    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("fuzzware_bindings.rs"))
        .expect("failed to write bindings");
}
