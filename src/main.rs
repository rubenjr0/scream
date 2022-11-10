use std::{sync::Arc, time::Instant};

use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
};

use tokio_stream::{wrappers::LinesStream, Stream};

use clap::{Parser, ValueEnum};
use eyre::Result;
use futures::StreamExt;
use hex::decode;
use sha2::{Digest, Sha256, Sha512};

#[derive(Clone, Copy, ValueEnum)]
enum HashMode {
    Sha256,
    Sha512,
}

#[derive(Parser)]
struct Args {
    hash_path: String,
    #[arg(value_enum)]
    hash_mode: HashMode,
    wordlist_path: String,
    chunk_size: Option<usize>,
}

async fn read_hash(path: &str) -> Result<Vec<u8>> {
    let f = File::open(path).await?;
    let mut reader = BufReader::new(f);
    let mut buffer = String::new();
    reader.read_to_string(&mut buffer).await?;
    let hash = buffer.trim();
    Ok(decode(hash)?)
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
    }
}

async fn read_wordlist(path: &str) -> Result<impl Stream<Item = String>> {
    let f = File::open(path).await?;
    let reader = BufReader::new(f);
    let line_stream = LinesStream::new(reader.lines()).map(|l| l.unwrap());
    Ok(line_stream)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let hash = read_hash(&args.hash_path).await?;
    let hash = Arc::new(hash);

    let read_time = Instant::now();
    let mut wordlist = read_wordlist(&args.wordlist_path).await?;
    let read_time = read_time.elapsed();
    println!(
        "Wordlist stream {} read in {read_time:?}",
        args.wordlist_path
    );

    let crack_time = Instant::now();

    let found = loop {
        if let Some(password) = wordlist.next().await {
            if gen_hash(password.as_bytes(), args.hash_mode) == *hash {
                break Some(password);
            }
        } else {
            break None;
        }
    };

    match found {
        Some(password) => {
            println!("Password found for the given hash: {password}")
        }
        _ => println!("No password found for the given hash"),
    }

    let crack_time = crack_time.elapsed();
    println!("Done in {crack_time:?}");

    Ok(())
}
