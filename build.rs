fn main() {
    cc::Build::new()
        .cpp(true)
        .flag("-std=c++20")
        .opt_level(1)
        .flag("-Wno-unused-parameter")
        .include("depends/bitcoin/src")
        .file("stubs/bitcoin-script.cpp")
        .compile("bitcoin-script.a");
}
