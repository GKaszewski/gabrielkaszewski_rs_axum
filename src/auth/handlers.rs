use rocket::get;
use rocket::response::status::Custom;
use rocket::serde::json::Json;
use rocket::{http::Status, post};
use rocket_db_pools::Connection;

use crate::auth::models::LoginData;
use crate::db::AppDatabase;

use super::{
    errors::UserError,
    models::{UserData, UserRead},
    service::{self, save_user},
};

#[post("/auth/users", data = "<user_data>")]
pub async fn create_user(
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

#[get("/auth/users")]
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

#[post("/auth/login", data = "<user_data>")]
pub async fn login(user_data: Json<LoginData>, db: Connection<AppDatabase>) -> Status {
    match service::login(user_data.0, db).await {
        Ok(_) => Status::Ok,
        Err(_) => Status::Unauthorized,
    }
}
