use std::{fs::File, net::SocketAddr, path::PathBuf, time::Duration};

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use pasetors::{
    keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey},
    version4::V4,
};

/// Server
#[derive(Debug, Parser)]
#[command(author = "scimas", version, about, long_about = None)]
struct Args {
    /// Path to the signing key for token generation
    ///
    /// This must be an ED25519 key.
    #[arg(long)]
    signing_key: String,

    /// Address for the server
    #[arg(long, default_value = "127.0.0.1:8080")]
    address: String,

    /// Use TLS
    #[arg(long)]
    secure: bool,

    /// Path to the directory containing the TLS key and certificate
    ///
    /// Required when using the `--secure` option
    #[arg(long)]
    tls_dir: Option<String>,

    /// Path to frontend assets
    #[arg(long)]
    frontend_dir: String,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::parse();

    let mut sign_key_file = File::open(&args.signing_key).unwrap();
    let paseto_key = read_key_pair(&mut sign_key_file).unwrap();

    let frontend_path = PathBuf::from(args.frontend_dir);
    let badam_sat_frontend_dir = frontend_path.join("badam-sat");
    let badam_sat_router =
        badam_sat_server::badam_sat_router(paseto_key.clone(), 1 << 6, badam_sat_frontend_dir);

    let judgment_frontend_dir = frontend_path.join("judgment");
    let (judgment_router, judgment_server) =
        judgment_server::judgment_router(paseto_key.clone(), 1 << 6, judgment_frontend_dir);
    {
        let judgment_server = judgment_server.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(240)).await;
                judgment_server.write().await.remove_finished_rooms();
            }
        });
    }

    let app_router = Router::new()
        .nest("/badam_sat", badam_sat_router)
        .nest("/judgment", judgment_router);

    let address: SocketAddr = args.address.parse().unwrap();

    if args.secure {
        let tls_dir = args
            .tls_dir
            .expect("`--tls-dir` needs to be specified when using `--secure`");
        let tls_config = RustlsConfig::from_pem_file(
            PathBuf::from(&tls_dir).join("cert.pem"),
            PathBuf::from(&tls_dir).join("key.pem"),
        )
        .await
        .unwrap();
        axum_server::bind_rustls(address, tls_config)
            .serve(app_router.into_make_service())
            .await
            .unwrap();
    } else {
        axum::Server::bind(&address)
            .serve(app_router.into_make_service())
            .await
            .unwrap();
    };
}

fn read_key_pair<T: std::io::Read>(reader: &mut T) -> std::io::Result<AsymmetricKeyPair<V4>> {
    let mut key_data = String::new();
    reader.read_to_string(&mut key_data).unwrap();
    let key = ed25519_compact::KeyPair::from_pem(&key_data).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "could not deserialize key from key data",
        )
    })?;
    let sk = AsymmetricSecretKey::<V4>::from(key.sk.as_ref()).expect("could not create secret key");
    let pk = AsymmetricPublicKey::<V4>::from(key.pk.as_ref()).expect("could not create public key");
    let paseto_key = AsymmetricKeyPair {
        secret: sk,
        public: pk,
    };
    Ok(paseto_key)
}
