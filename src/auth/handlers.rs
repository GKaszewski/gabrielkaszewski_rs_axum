use rocket::get;
use rocket::http::CookieJar;
use rocket::response::status::Custom;
use rocket::serde::json::Json;
use rocket::{http::Status, post};
use rocket_db_pools::Connection;

use crate::auth::models::LoginData;
use crate::db::AppDatabase;

use super::guards::{AdminGuard, AuthGuard};
use super::{
    errors::UserError,
    models::{UserData, UserRead},
    service::{self, save_user},
};

#[post("/users", data = "<user_data>")]
pub async fn create_user(
    _auth_guard: AdminGuard,
    user_data: Json<UserData<'_>>,
    db: Connection<AppDatabase>,
) -> Result<Json<UserRead>, Custom<&'static str>> {
    let new_user = service::create_user(user_data.0).map_err(|e| match e {
        UserError::PasswordTooShort => Custom(Status::BadRequest, "Password too short"),
        UserError::PasswordTooWeak => Custom(Status::BadRequest, "Password too weak"),
        _ => Custom(Status::BadRequest, "Failed to create user"),
    })?;

    let user = save_user(new_user, db).await;

    match user {
        Ok(user) => Ok(Json(UserRead {
            id: user.id,
            username: user.username,
            is_superuser: user.is_superuser,
            created_at: user.created_at,
            updated_at: user.updated_at,
        })),
        Err(_) => Err(Custom(Status::InternalServerError, "Failed to create user")),
    }
}

#[get("/users")]
pub async fn get_users(
    db: Connection<AppDatabase>,
) -> Result<Json<Vec<UserRead>>, Custom<&'static str>> {
    let users = service::get_users(db).await;

    match users {
        Ok(users) => Ok(Json(
            users
                .into_iter()
                .map(|user| UserRead {
                    id: user.id,
                    username: user.username,
                    is_superuser: user.is_superuser,
                    created_at: user.created_at,
                    updated_at: user.updated_at,
                })
                .collect(),
        )),
        Err(_) => Err(Custom(Status::InternalServerError, "Failed to get users")),
    }
}

#[post("/login", data = "<user_data>")]
pub async fn login<'r>(user_data: Json<LoginData>, db: Connection<AppDatabase>, cookie_jar: &'r CookieJar<'_>) -> Status {
    match service::login(user_data.0, db, cookie_jar).await {
        Ok(_) => Status::Ok,
        Err(_) => Status::NotFound,
    }
}

#[post("/logout")]
pub fn logout<'r>(cookie_jar: &'r CookieJar<'_>) -> Status {
    service::logout(cookie_jar);
    Status::Ok
}

#[get("/me")]
pub async fn me(auth: AuthGuard) -> Json<UserRead> {
    Json(UserRead {
        id: auth.0.id,
        username: auth.0.username,
        is_superuser: auth.0.is_superuser,
        created_at: auth.0.created_at,
        updated_at: auth.0.updated_at,
    })
}

#[get("/admin")]
pub async fn admin(auth: AdminGuard) -> Json<UserRead> {
    Json(UserRead {
        id: auth.0.id,
        username: auth.0.username,
        is_superuser: auth.0.is_superuser,
        created_at: auth.0.created_at,
        updated_at: auth.0.updated_at,
    })  
}