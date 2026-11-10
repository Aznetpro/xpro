use anyhow::Result;
use log::info;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

/// Handle TLS connections - passthrough to backend.
pub async fn handle_tls(socket: TcpStream) -> Result<()> {
    info!("TLS detectado - passthrough para backend...");
    socket.set_nodelay(true)?;

    // Tentar SSH primeiro (Porta 22).
    match TcpStream::connect("127.0.0.1:22").await {
        Ok(remote) => {
            remote.set_nodelay(true)?;
            info!("TLS -> SSH:22 conectado");
            let (cr, cw) = socket.into_split();
            let (sr, sw) = remote.into_split();
            let cr = Arc::new(Mutex::new(cr));
            let cw = Arc::new(Mutex::new(cw));
            let sr = Arc::new(Mutex::new(sr));
            let sw = Arc::new(Mutex::new(sw));
            tokio::try_join!(transfer_data(cr, sw), transfer_data(sr, cw))?;
            Ok(())
        }
        Err(_) => {
            // Se SSH falhar, tentar VPN (Porta 1194).
            match TcpStream::connect("127.0.0.1:1194").await {
                Ok(remote) => {
                    remote.set_nodelay(true)?;
                    info!("TLS -> VPN:1194 conectado");
                    let (cr, cw) = socket.into_split();
                    let (sr, sw) = remote.into_split();
                    let cr = Arc::new(Mutex::new(cr));
                    let cw = Arc::new(Mutex::new(cw));
                    let sr = Arc::new(Mutex::new(sr));
                    let sw = Arc::new(Mutex::new(sw));
                    tokio::try_join!(transfer_data(cr, sw), transfer_data(sr, cw))?;
                    Ok(())
                }
                Err(e) => {
                    info!("Falha no passthrough TLS: {}", e);
                    Err(e.into())
                }
            }
        }
    }
}

/// HCR: termina TLS no Xpro e encaminha o SSH já descriptografado ao sshd.
/// O cliente pode aceitar o certificado autoassinado quando usa "Allow insecure".
pub async fn handle_hcr(socket: TcpStream) -> Result<()> {
    socket.set_nodelay(true)?;
    let config = build_server_config("/opt/mpro/cert.pem", "/opt/mpro/key.pem")?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let mut tls_stream = acceptor.accept(socket).await?;
    let mut ssh = TcpStream::connect("127.0.0.1:22").await?;
    ssh.set_nodelay(true)?;
    info!("HCR TLS terminado -> SSH:22 conectado");
    tokio::io::copy_bidirectional(&mut tls_stream, &mut ssh).await?;
    Ok(())
}

fn build_server_config(cert_path: &str, key_path: &str) -> Result<rustls::ServerConfig> {
    let cert_file = std::fs::File::open(cert_path)?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    let key_bytes = std::fs::read(key_path)?;
    let mut pkcs8_reader = std::io::BufReader::new(key_bytes.as_slice());
    let key = rustls_pemfile::pkcs8_private_keys(&mut pkcs8_reader)?
        .into_iter()
        .next()
        .or_else(|| {
            let mut rsa_reader = std::io::BufReader::new(key_bytes.as_slice());
            rustls_pemfile::rsa_private_keys(&mut rsa_reader)
                .ok()
                .and_then(|mut keys| keys.drain(..).next())
        })
        .map(PrivateKey)
        .ok_or_else(|| anyhow::anyhow!("nenhuma chave PKCS#8 ou RSA encontrada em {key_path}"))?;

    Ok(rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?)
}

async fn transfer_data(
    read_stream: Arc<Mutex<tokio::net::tcp::OwnedReadHalf>>,
    write_stream: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
) -> Result<()> {
    let mut buffer = [0; 32768];
    loop {
        let bytes_read = {
            let mut read_guard = read_stream.lock().await;
            read_guard.read(&mut buffer).await?
        };
        if bytes_read == 0 {
            break;
        }
        let mut write_guard = write_stream.lock().await;
        write_guard.write_all(&buffer[..bytes_read]).await?;
    }
    Ok(())
}
