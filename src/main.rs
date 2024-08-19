// use dotenv::dotenv;
// use sqlx::postgres::{PgPool, PgPoolOptions};
// use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// use std::time::Duration;

use db::{run_migrations, AppDatabase};
use rocket::fairing::AdHoc;
use rocket::{fs::FileServer, launch, routes};
use rocket_db_pools::Database;

mod auth;
mod db;
mod file_manager;
mod projects;
mod skills;
mod web;
mod work_experience;

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(AppDatabase::init())
        .attach(AdHoc::try_on_ignite("DB Migrations", run_migrations))
        .mount("/assets", FileServer::from("assets"))
        .mount("/auth", auth::router::routes())
        .mount(
            "/",
            routes![
                web::handlers::index,
            ],
        )
}
