/// Uses `tonic-build` to build the defined protobufs into Rust code
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/dams_rpc.proto")?;
    Ok(())
}
