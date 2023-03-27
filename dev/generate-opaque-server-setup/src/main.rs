use lock_keeper::config::opaque::OpaqueCipherSuite;
use opaque_ke::ServerSetup;
use rand::rngs::StdRng;
use rand::SeedableRng;

fn main() {
    let mut rng = StdRng::from_entropy();

    let server_setup = ServerSetup::<OpaqueCipherSuite>::new(&mut rng);
    let server_setup_bytes = bincode::serialize(&server_setup).unwrap();
    println!("{}", base64::encode(&server_setup_bytes));
}
