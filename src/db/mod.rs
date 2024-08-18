use rocket::fairing::{self};
use rocket::{Build, Rocket};

use rocket_db_pools::{sqlx::PgPool, Database};

#[derive(Database)]
#[database("gabrielkaszewski_rs")]
pub struct AppDatabase(pub PgPool);

pub async fn run_migrations(rocket: Rocket<Build>) -> fairing::Result {
    if let Some(db) = AppDatabase::fetch(&rocket) {
        sqlx::migrate!("./migrations")
            .run(&db.0)
            .await
            .expect("Failed to run migrations");
        Ok(rocket)
    } else {
        Err(rocket)
    }
}
