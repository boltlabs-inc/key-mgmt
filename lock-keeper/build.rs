use std::env;
use std::path::PathBuf;

/// Uses `tonic-build` to build the defined protobufs into Rust code
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_file = "./proto/lock_keeper_rpc.proto";
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    tonic_build::configure()
        .build_server(true)
        .file_descriptor_set_path("./src/lock_keeper_description.bin")
        .out_dir(out_dir)
        .compile(&[proto_file], &["."])?;
    Ok(())
}
