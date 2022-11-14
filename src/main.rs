use std::{
    collections::HashSet,
    io::SeekFrom,
    sync::{Arc, RwLock},
    time::Instant,
};

use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncSeekExt, BufReader},
};

use tokio_stream::{wrappers::LinesStream, Stream};

use clap::{Parser, ValueEnum};
use eyre::Result;
use futures::{future::try_join_all, StreamExt};
use sha2::{Digest, Sha256, Sha512};

type Hash = Vec<u8>;

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

async fn read_file_stream(path: &str) -> Result<impl Stream<Item = String>> {
    let f = File::open(path).await?;
    let reader = BufReader::new(f);
    let line_stream = LinesStream::new(reader.lines()).map(|l| l.unwrap());
    Ok(line_stream)
}

async fn read_hashes(path: &str) -> Result<Vec<Hash>> {
    let hashes = read_file_stream(path).await?;
    let hashes: HashSet<Hash> = hashes
        .map(|hash| hex::decode(hash).unwrap())
        .collect()
        .await;
    Ok(hashes.into_iter().collect())
}

async fn read_wordlist(path: &str) -> Result<Vec<impl Stream<Item = String>>> {
    let f = File::open(path).await?;
    let s = f.metadata().await?.len() as usize;
    let n = num_cpus::get();
    println!("{n} CPUs");
    let spn = s / n;
    let mut streams = Vec::with_capacity(n);
    for i in 0..n {
        let f = File::open(path).await?;
        let mut r = BufReader::with_capacity(spn, f);
        r.seek(SeekFrom::Start((i * spn) as u64)).await?;
        streams.push(LinesStream::new(r.lines()).map(|l| l.unwrap()));
    }
    Ok(streams)
}

#[inline]
fn gen_hash(data: &[u8], hash_mode: HashMode) -> Hash {
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let hashes = read_hashes(&args.hashes_path).await?;
    println!("{} hashes loaded", hashes.len());
    let hashes = RwLock::new(hashes);
    let hashes = Arc::new(hashes);

    let read_time = Instant::now();
    let wordlist = read_wordlist(&args.wordlist_path).await?;
    let read_time = read_time.elapsed();
    println!(
        "Wordlist streams for {} read in {read_time:?}",
        args.wordlist_path
    );

    let crack_time = Instant::now();
    let mut tasks = Vec::new();
    for mut chunk in wordlist {
        let hashes = hashes.clone();
        let task = tokio::spawn(async move {
            loop {
                if hashes.read().unwrap().len() == 0 {
                    break;
                }
                if let Some(password) = chunk.next().await {
                    let h = hashes.read().unwrap().clone();
                    for (hash_idx, hash) in h.iter().enumerate() {
                        if &gen_hash(password.as_bytes(), args.hash_mode) == hash {
                            println!(
                                "{} --- {password:<16} [{:>14?}]",
                                hex::encode(hash),
                                crack_time.elapsed()
                            );
                            hashes.write().unwrap().remove(hash_idx);
                            break;
                        }
                    }
                }
            }
        });
        tasks.push(task);
    }
    try_join_all(tasks).await?;
    let crack_time = crack_time.elapsed();
    let hashes = hashes.read().unwrap();
    if hashes.len() > 0 {
        println!("\nNo password found for the given hashes (search took {crack_time:6?}):");
        for hash in hashes.iter() {
            println!("> {}", hex::encode(hash));
        }
    }

    Ok(())
}
