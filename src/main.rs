use std::{
    io::SeekFrom,
    sync::{atomic::AtomicBool, Arc},
    time::Instant,
};

use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader},
};

use tokio_stream::{wrappers::LinesStream, Stream};

use clap::{Parser, Subcommand, ValueEnum};
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

#[derive(Subcommand)]
enum CrackMode {
    Dictionary { path: String },
    Bruteforce,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Args {
    hash_path: String,
    #[arg(value_enum)]
    hash_mode: HashMode,
    #[command(subcommand)]
    crack_mode: CrackMode,
}

async fn read_hash(path: &str) -> Result<Hash> {
    let f = File::open(path).await?;
    let mut r = BufReader::new(f);
    let mut hash = String::new();
    r.read_to_string(&mut hash).await?;
    Ok(hex::decode(hash.trim())?)
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

async fn crack_with_wordlist(hash: Hash, wordlist_path: &str, hash_mode: HashMode) -> Result<()> {
    let wordlist = read_wordlist(wordlist_path).await?;
    let mut tasks = Vec::new();
    let found = Arc::new(AtomicBool::new(false));
    let crack_time = Instant::now();
    for mut chunk in wordlist {
        let found = found.clone();
        let hash = hash.clone();
        let task = tokio::spawn(async move {
            loop {
                if found.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                if let Some(password) = chunk.next().await {
                    if gen_hash(password.as_bytes(), hash_mode) == *hash {
                        println!(
                            "{} --- {password:<16} [{:>14?}]",
                            hex::encode(&*hash),
                            crack_time.elapsed()
                        );
                        found.fetch_or(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                }
            }
        });
        tasks.push(task);
    }
    try_join_all(tasks).await?;
    let crack_time = crack_time.elapsed();
    if !found.load(std::sync::atomic::Ordering::Relaxed) {
        println!("No password found for the given hash (search took {crack_time:6?}):");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let hash = read_hash(&args.hash_path).await?;
    // let hash = Arc::new(hash);

    // TODO:
    // 1. Extract to function and add good multi hash support
    // 2. Extract to 2 separate functions, one for single hash, one for multi hash
    match args.crack_mode {
        CrackMode::Dictionary { path } => crack_with_wordlist(hash, &path, args.hash_mode).await?,
        CrackMode::Bruteforce => todo!("implement bruteforce"),
    }

    Ok(())
}
