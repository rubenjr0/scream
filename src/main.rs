use rayon::ThreadPoolBuilder;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    time::Instant,
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

    let read_time = Instant::now();
    let wordlist = read_wordlist(&args.wordlist_path).await?;
    let read_time = read_time.elapsed();
    println!(
        "Wordlinst stream {} read in {read_time:?}",
        args.wordlist_path
    );

    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut tx = Some(tx);

    let tp = ThreadPoolBuilder::new().build()?;

    let crack_time = Instant::now();
    let mut chunks = wordlist.chunks(u16::MAX as usize);
    while let Some(chunk) = chunks.next().await {
        if tx.is_none() {
            break;
        }
        tp.install(|| {
            for password in chunk {
                if tx.is_some() {
                    let h = gen_hash(password.as_bytes(), args.hash_mode);
                    if h == hash {
                        println!("{password} -> {}", hex::encode(&h));
                        if let Some(sender) = tx.take() {
                            sender.send(password).unwrap();
                            println!("Breaking");
                            return;
                        }
                    }
                } else {
                    return;
                }
            }
        });
    }
    let crack_time = crack_time.elapsed();

    match rx.await {
        Ok(password) => {
            println!("Password found for the given hash: {password} in {crack_time:?}")
        }
        Err(err) => println!("No password found for the given hash: {err}"),
    }

    Ok(())
}
