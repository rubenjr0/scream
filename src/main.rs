use std::{
    collections::{HashMap, HashSet},
    io::Write,
    time::Instant,
};

use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};

use tokio_stream::{wrappers::LinesStream, Stream};

use clap::{Parser, ValueEnum};
use eyre::Result;
use futures::StreamExt;
use sha2::{Digest, Sha256, Sha512};

#[derive(Clone, Copy, ValueEnum)]
enum HashMode {
    Sha256,
    Sha512,
    MD5,
}

#[derive(Parser)]
struct Args {
    hashes_path: String,
    #[arg(value_enum)]
    hash_mode: HashMode,
    wordlist_path: String,
}

async fn read_hashes(path: &str) -> Result<HashMap<Vec<u8>, bool>> {
    let hashes = read_file_stream(path).await?;
    let hashes: HashSet<Vec<u8>> = hashes
        .map(|hash| hex::decode(hash).unwrap())
        .collect()
        .await;
    Ok(hashes.into_iter().map(|hash| (hash, false)).collect())
}

fn gen_hash(data: &[u8], hash_mode: HashMode) -> Vec<u8> {
    match hash_mode {
        HashMode::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashMode::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashMode::MD5 => md5::compute(data).to_vec(),
    }
}

async fn read_file_stream(path: &str) -> Result<impl Stream<Item = String>> {
    let f = File::open(path).await?;
    let reader = BufReader::new(f);
    let line_stream = LinesStream::new(reader.lines()).map(|l| l.unwrap());
    Ok(line_stream)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut hashes = read_hashes(&args.hashes_path).await?;
    println!("{} hashes loaded", hashes.len());

    let read_time = Instant::now();
    let mut wordlist = read_file_stream(&args.wordlist_path).await?;
    let read_time = read_time.elapsed();
    println!(
        "Wordlist stream {} read in {read_time:?}",
        args.wordlist_path
    );

    let mut left = hashes.iter().filter(|(_, found)| !*found).count();
    let mut stdout_lock = std::io::stdout().lock();
    let crack_time = Instant::now();
    loop {
        if left == 0 {
            break;
        }
        if let Some(password) = wordlist.next().await {
            for (hash, found) in hashes.iter_mut().filter(|(_, found)| !**found) {
                if &gen_hash(password.as_bytes(), args.hash_mode) == hash {
                    writeln!(
                        stdout_lock,
                        "{} - {password:<16} [{:^16?}]",
                        hex::encode(hash),
                        crack_time.elapsed()
                    )?;
                    stdout_lock.flush()?;
                    *found = true;
                    left -= 1;
                }
            }
        }
    }
    let crack_time = crack_time.elapsed();

    if left > 0 {
        let pending = hashes.into_iter().filter(|(_, found)| !found);
        println!("\nNo password found for the given hashes (search took {crack_time:6?}):");
        for (hash, _) in pending {
            println!("> {}", hex::encode(hash));
        }
    }

    Ok(())
}
