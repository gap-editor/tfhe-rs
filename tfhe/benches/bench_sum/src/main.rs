use std::time::Instant;
use tfhe::prelude::*;
use tfhe::{set_server_key, ClientKey, CompressedServerKey, ConfigBuilder, FheUint64};
use rand::Rng;

fn main()
{
    let config = ConfigBuilder::default().build();
    let client_key = ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);

    let cpu_sk = compressed_server_key.decompress();
    // let gpu_sk = compressed_server_key.decompress_to_gpu();

    let mut rng = rand::thread_rng();
    let clear_vals: Vec<u64> = (0..32).map(|_| rng.r#gen()).collect();
    let clear_sum: u64 = clear_vals.iter().sum();
    let ciphertexts: Vec<FheUint64> = clear_vals
        .iter()
        .map(|&v| FheUint64::encrypt(v, &client_key))
        .collect();
    let ciphertext_refs: Vec<&FheUint64> = ciphertexts.iter().collect();

    set_server_key(cpu_sk);
    let t_cpu = Instant::now();
    let res_cpu = FheUint64::sum(&ciphertext_refs);
    let cpu_lat_ms = t_cpu.elapsed().as_millis();
    let dec_cpu: u64 = res_cpu.decrypt(&client_key);
    assert_eq!(dec_cpu, clear_sum);
    println!("Latency sum(32 x FheUint64) on CPU : {} ms", cpu_lat_ms);

    // set_server_key(gpu_sk);
    // let t_gpu = Instant::now();
    // let res_gpu = FheUint64::sum(&ciphertext_refs);
    // let gpu_lat_ms = t_gpu.elapsed().as_millis();
    // let dec_gpu: u64 = res_gpu.decrypt(&client_key);
    // assert_eq!(dec_gpu, clear_sum);
    // println!("Latency sum(32 x FheUint64) on GPU : {} ms", gpu_lat_ms);
}
