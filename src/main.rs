use argon2::password_hash::PasswordHash;
use argon2::{Argon2, PasswordVerifier};
use axum::{
    Router,
    extract::{Form, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    serve,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use lettre::{AsyncTransport, Message};
use rand::Rng;
use reqwest::Client;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio::main;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;

#[derive(Deserialize)]
struct QuoteInput {
    from: String,
    to: String,
    quantity: f64, // kg
    material: String,
    email: Option<String>, // Optional for email send
}

#[derive(Serialize, Deserialize)]
struct PostcodeResponse {
    result: PostcodeResult,
}

#[derive(Serialize, Deserialize)]
struct PostcodeResult {
    latitude: f64,
    longitude: f64,
}

#[derive(Serialize, Deserialize)]
struct OsrmResponse {
    routes: Vec<OsrmRoute>,
}

#[derive(Serialize, Deserialize)]
struct OsrmRoute {
    distance: f64, // Meters
}

#[derive(Clone)]
struct AppState {
    admin_username: String,
    admin_password_hash: String,
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    sender_email: String,
}

#[main]
async fn main() {
    // Init DB and create table if not exists
    let conn = Connection::open("quotes.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS quotes (
            id INTEGER PRIMARY KEY,
            from_post TEXT NOT NULL,
            to_post TEXT NOT NULL,
            quantity_kg REAL NOT NULL,
            material TEXT NOT NULL,
            distance_km REAL NOT NULL,
            cost REAL NOT NULL,
            timestamp TEXT NOT NULL
        )",
        [],
    )
    .unwrap();

    let admin_username = env::var("ADMIN_USERNAME").expect("Set ADMIN_USERNAME env var");
    let admin_password_hash =
        env::var("ADMIN_PASSWORD_HASH").expect("Set ADMIN_PASSWORD_HASH env var");

    let smtp_host = env::var("SMTP_HOST").expect("Set SMTP_HOST env var");
    let smtp_port: u16 = env::var("SMTP_PORT")
        .expect("Set SMTP_PORT env var")
        .parse()
        .expect("Invalid port");
    let smtp_username = env::var("SMTP_USERNAME").expect("Set SMTP_USERNAME env var");
    let smtp_password = env::var("SMTP_PASSWORD").expect("Set SMTP_PASSWORD env var");

    let creds = Credentials::new(smtp_username.clone(), smtp_password);
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_host)
        .expect("Failed to create transport")
        .credentials(creds)
        .port(smtp_port)
        .build();

    let shared_state = Arc::new(AppState {
        admin_username,
        admin_password_hash,
        mailer,
        sender_email: smtp_username,
    });

    let app = Router::new()
        .route("/quote", post(calculate_quote))
        .route("/admin/login", get(login_form).post(handle_login))
        .route("/admin/logout", get(handle_logout))
        .route(
            "/admin/quotes",
            get(list_quotes).layer(middleware::from_fn_with_state(
                shared_state.clone(),
                auth_middleware,
            )),
        )
        .nest_service("/", ServeDir::new("public"))
        .with_state(shared_state);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(listener, app).await.unwrap();
}

#[axum::debug_handler]
async fn calculate_quote(
    State(state): State<Arc<AppState>>,
    Form(input): Form<QuoteInput>,
) -> Result<Html<String>, StatusCode> {
    if input.from.is_empty() || input.to.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let client = Client::new();

    let from_coords = match get_coords(&client, &input.from).await {
        Ok(coords) => coords,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let to_coords = match get_coords(&client, &input.to).await {
        Ok(coords) => coords,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let distance_km = match get_distance(&client, from_coords, to_coords).await {
        Ok(dist) => dist,
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let quantity_tons = input.quantity / 1000.0;
    let base_fee = 50.0;
    let per_km = 5.0;
    let per_ton = 10.0;
    let calculated_cost = base_fee + (distance_km * per_km) + (quantity_tons * per_ton);
    let min_cost = 50.0;
    let cost = calculated_cost.max(min_cost);

    // Log to DB
    let conn = Connection::open("quotes.db").unwrap();
    let timestamp = OffsetDateTime::now_utc().to_string();
    conn.execute(
        "INSERT INTO quotes (from_post, to_post, quantity_kg, material, distance_km, cost, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![input.from, input.to, input.quantity, input.material, distance_km, cost, timestamp],
    ).unwrap();

    // Send email if provided
    if let Some(recipient) = input.email {
        println!("Debug: Email field provided - recipient: {}", recipient);

        let email_body = format!(
            r#"
            <h2>Your Hauling Quote</h2>
            <p>From: {}</p>
            <p>To: {}</p>
            <p>Quantity: {} kg of {}</p>
            <p>Distance: {:.1} km</p>
            <p>Total Cost: £{:.2}</p>
            <p>Thank you for using our service!</p>
            "#,
            input.from, input.to, input.quantity, input.material, distance_km, cost
        );

        let email = match Message::builder()
            .from(state.sender_email.parse().unwrap())
            .to(recipient.parse().unwrap())
            .subject("Your Hauling Quote Details")
            .header(ContentType::TEXT_HTML)
            .body(email_body)
        {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("Debug: Message build failed: {:?}", e);
                // Continue to return quote HTML even if email fails
                return Ok(Html(format!(
                    "<h2>Estimated Quote</h2>
                         <p>From: {}</p>
                         <p>To: {}</p>
                         <p>Quantity: {} kg of {}</p>
                         <p>Distance: {:.1} km</p>
                         <p>Total Cost: £{:.2}</p>",
                    input.from, input.to, input.quantity, input.material, distance_km, cost
                )));
            }
        };

        match state.mailer.clone().send(email).await {
            Ok(_) => println!("Debug: Email sent successfully"),
            Err(e) => eprintln!("Debug: Email send failed: {:?}", e),
        };
    } else {
        println!("Debug: No email field provided - skipping send");
    }

    Ok(Html(format!(
        "<h2>Estimated Quote</h2>
         <p>From: {}</p>
         <p>To: {}</p>
         <p>Quantity: {} kg of {}</p>
         <p>Distance: {:.1} km</p>
         <p>Total Cost: £{:.2}</p>",
        input.from, input.to, input.quantity, input.material, distance_km, cost
    )))
}

async fn get_coords(client: &Client, postcode: &str) -> Result<(f64, f64), ()> {
    let url = format!(
        "https://api.postcodes.io/postcodes/{}",
        postcode.replace(" ", "%20")
    );
    let resp = client.get(&url).send().await.map_err(|_| ())?;
    let data: PostcodeResponse = resp.json().await.map_err(|_| ())?;
    Ok((data.result.latitude, data.result.longitude))
}

async fn get_distance(client: &Client, from: (f64, f64), to: (f64, f64)) -> Result<f64, ()> {
    let url = format!(
        "http://router.project-osrm.org/route/v1/driving/{},{};{},{}?overview=false",
        from.1, from.0, to.1, to.0
    );
    let resp = client.get(&url).send().await.map_err(|_| ())?;
    let data: OsrmResponse = resp.json().await.map_err(|_| ())?;
    Ok(data.routes[0].distance / 1000.0)
}

async fn login_form() -> Html<String> {
    Html(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Admin Login</title>
            <link rel="stylesheet" href="/styles.css">
        </head>
        <body>
            <h2>Admin Login</h2>
            <form method="post" action="/admin/login">
                <label>Username: <input type="text" name="username"></label><br>
                <label>Password: <input type="password" name="password"></label><br>
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
    "#
        .to_string(),
    )
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[axum::debug_handler]
async fn handle_login(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> (CookieJar, Result<Redirect, Html<String>>) {
    let parsed_hash = match PasswordHash::new(&state.admin_password_hash) {
        Ok(h) => h,
        Err(_) => return (jar, Err(Html("<p>Invalid hash format</p>".to_string()))),
    };

    if form.username == state.admin_username
        && Argon2::default()
            .verify_password(form.password.as_bytes(), &parsed_hash)
            .is_ok()
    {
        let session_token = rand::thread_rng()
            .r#gen::<[u8; 32]>()
            .iter()
            .map(|&b| format!("{:02x}", b))
            .collect::<String>();
        let cookie = Cookie::build(("session", session_token))
            .path("/")
            .secure(false) // Change to true for production
            .http_only(true)
            .build();
        (jar.add(cookie), Ok(Redirect::to("/admin/quotes")))
    } else {
        (jar, Err(Html("<p>Invalid credentials</p>".to_string())))
    }
}

async fn handle_logout(jar: CookieJar) -> (CookieJar, Redirect) {
    let cookie = Cookie::build(("session", ""))
        .path("/")
        .max_age(Duration::ZERO)
        .build();
    (jar.add(cookie), Redirect::to("/admin/login"))
}

async fn auth_middleware(
    State(_state): State<Arc<AppState>>,
    jar: CookieJar,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session") {
        if !session_cookie.value().is_empty() {
            return next.run(req).await;
        }
    }
    Redirect::to("/admin/login").into_response()
}

#[axum::debug_handler]
async fn list_quotes() -> Html<String> {
    let conn = Connection::open("quotes.db").unwrap();
    let mut stmt = conn
        .prepare("SELECT * FROM quotes ORDER BY id DESC")
        .unwrap();
    let quotes = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, f64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, f64>(5)?,
                row.get::<_, f64>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .unwrap();

    let mut table_rows = String::new();
    for quote in quotes {
        let (id, from, to, kg, material, km, cost, time) = quote.unwrap();
        table_rows += &format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.1}</td><td>£{:.2}</td><td>{}</td></tr>",
            id, from, to, kg, material, km, cost, time
        );
    }

    let html = format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Admin Quotes</title>
            <link rel="stylesheet" href="/admin.css">
        </head>
        <body>
            <h2>Saved Quotes</h2>
            <table>
                <tr>
                    <th>ID</th><th>From</th><th>To</th><th>Kg</th><th>Material</th><th>Km</th><th>Cost</th><th>Time</th>
                </tr>
                {table_rows}
            </table>
            <a href="/admin/logout">Logout</a>
        </body>
        </html>
        "#,
    );

    Html(html)
}
