/// Uses `tonic-build` to build the defined protobufs into Rust code
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/blob_server_rpc.proto")?;
    Ok(())
}
