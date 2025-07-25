use dotenvy::dotenv;
use mongodb::bson::doc;
use mongodb::options::{ClientOptions, Tls, TlsOptions};
use mongodb::{Client, Database};
use std::env;

pub async fn connect_db() -> Result<Database, Box<dyn std::error::Error>> {
    dotenv().ok();

    let uri = env::var("MONGO_URI").expect("MONGO_URI must be set");

    let mut client_options = ClientOptions::parse(&uri).await?;

    client_options.app_name = Some("DoubleBlind App".to_string());
    client_options.max_pool_size = Some(50);
    client_options.server_selection_timeout = Some(std::time::Duration::from_secs(5));

    let tls_options = TlsOptions::builder()
        .allow_invalid_certificates(false)
        .build();

    client_options.tls = Some(Tls::Enabled(tls_options));

    let client = Client::with_options(client_options)?;

    client
        .database("admin")
        .run_command(doc! {"ping": 1}, None)
        .await?;

    Ok(client.database("double_blind"))
}