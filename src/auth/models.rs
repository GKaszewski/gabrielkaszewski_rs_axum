use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

use super::service::UserBuilder;

#[derive(Debug, Serialize, Deserialize, FromRow)]
#[serde(crate = "rocket::serde")]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password: String, // this is a hashed password
    pub is_superuser: bool,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

impl User {
    pub fn builder() -> UserBuilder {
        UserBuilder::new()
    }
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct UserData<'r> {
    pub username: &'r str,
    pub password: &'r str,
    pub is_superuser: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct UserRead {
    pub id: i32,
    pub username: String,
    pub is_superuser: bool,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct LoginData {
    pub username: String,
    pub password: String,
}
