use std::time::Instant;
use rand::Rng;
use tfhe::{ClientKey, ConfigBuilder, CompressedServerKey, FheUint64, set_server_key};
use tfhe::prelude::{FheDecrypt, FheEncrypt};

fn main() {
    let config = ConfigBuilder::default().build();
    let client_key = ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);

    #[cfg(not(feature = "gpu"))]
    let cpu_sk = compressed_server_key.decompress();

    #[cfg(feature = "gpu")]
    let gpu_sk = compressed_server_key.decompress_to_gpu();

    const N: usize = 32;
    const WARMUP: usize = 50;
    const EXPERIMENTS: usize = 100;

    #[cfg(not(feature = "gpu"))]
    {
        set_server_key(cpu_sk);

        println!("Warming up...");
        for _ in 0..WARMUP {
            let mut rng = rand::thread_rng();
            let clear_vals: Vec<u64> = (0..N).map(|_| rng.r#gen()).collect();
            let clear_sum: u64 = clear_vals.iter().sum();

            let ciphertexts: Vec<FheUint64> = clear_vals
              .iter()
              .map(|&v| FheUint64::encrypt(v, &client_key))
              .collect();
            let ciphertext_refs: Vec<&FheUint64> = ciphertexts.iter().collect();

            let result_cpu = FheUint64::sum(&ciphertext_refs);
            let decrypted_cpu: u64 = result_cpu.decrypt(&client_key);
            assert_eq!(decrypted_cpu, clear_sum);
        }

        let mut cpu_latencies: Vec<u128> = Vec::with_capacity(EXPERIMENTS);
        for i in 0..EXPERIMENTS {
            let mut rng = rand::thread_rng();
            let clear_vals: Vec<u64> = (0..N).map(|_| rng.r#gen()).collect();
            let clear_sum: u64 = clear_vals.iter().sum();

            let ciphertexts: Vec<FheUint64> = clear_vals
              .iter()
              .map(|&v| FheUint64::encrypt(v, &client_key))
              .collect();
            let ciphertext_refs: Vec<&FheUint64> = ciphertexts.iter().collect();

            let t0 = Instant::now();
            let result_cpu = FheUint64::sum(&ciphertext_refs);
            let elapsed_cpu = t0.elapsed().as_millis();
            cpu_latencies.push(elapsed_cpu);

            let decrypted_cpu: u64 = result_cpu.decrypt(&client_key);
            assert_eq!(decrypted_cpu, clear_sum);

            println!(
                "Iteration {:>3} – latency sum(32 x FheUint64) on CPU: {} ms",
                i + 1,
                elapsed_cpu
            );
        }

        let total_cpu: u128 = cpu_latencies.iter().sum();
        let average_cpu = total_cpu as f64 / cpu_latencies.len() as f64;
        println!(
            "\nAverage CPU latency over {} iterations: {:.2} ms",
            EXPERIMENTS,
            average_cpu
        );   
    }

    #[cfg(feature = "gpu")]
    {
        set_server_key(gpu_sk);

        println!("Warming up...");
        for _ in 0..WARMUP {
            let mut rng = rand::thread_rng();
            let clear_vals: Vec<u64> = (0..N).map(|_| rng.r#gen()).collect();
            let clear_sum: u64 = clear_vals.iter().sum();

            let ciphertexts: Vec<FheUint64> = clear_vals
                .iter()
                .map(|&v| FheUint64::encrypt(v, &client_key))
                .collect();
            let ciphertext_refs: Vec<&FheUint64> = ciphertexts.iter().collect();

            let result_gpu = FheUint64::sum(&ciphertext_refs);
            let decrypted_gpu: u64 = result_gpu.decrypt(&client_key);
            assert_eq!(decrypted_gpu, clear_sum);
        }

        let mut gpu_latencies: Vec<u128> = Vec::with_capacity(EXPERIMENTS);
        for i in 0..EXPERIMENTS {
            let mut rng = rand::thread_rng();
            let clear_vals: Vec<u64> = (0..N).map(|_| rng.r#gen()).collect();
            let clear_sum: u64 = clear_vals.iter().sum();

            let ciphertexts: Vec<FheUint64> = clear_vals
                .iter()
                .map(|&v| FheUint64::encrypt(v, &client_key))
                .collect();
            let ciphertext_refs: Vec<&FheUint64> = ciphertexts.iter().collect();

            let t0 = Instant::now();
            let result_gpu = FheUint64::sum(&ciphertext_refs);
            let elapsed_gpu = t0.elapsed().as_millis();
            gpu_latencies.push(elapsed_gpu);

            let decrypted_gpu: u64 = result_gpu.decrypt(&client_key);
            assert_eq!(decrypted_gpu, clear_sum);

            println!(
                "Iteration {:>3} – latency sum(32 x FheUint64) on GPU: {} ms",
                i + 1,
                elapsed_gpu
            );
        }

        let total_gpu: u128 = gpu_latencies.iter().sum();
        let average_gpu = total_gpu as f64 / gpu_latencies.len() as f64;
        println!(
            "\nAverage GPU latency over {} iterations: {:.2} ms",
            EXPERIMENTS,
            average_gpu
        );
    }
}
