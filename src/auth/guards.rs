use rocket::async_trait;
use rocket::request::{self, Request, FromRequest};
use rocket::http::Status;
use rocket_db_pools::Connection;
use crate::db::AppDatabase;
use rocket::outcome::Outcome::{Success, Error};

use super::models::User;
use super::errors::AuthError;
use super::service::authorize_user;

pub struct AuthGuard(pub User);

pub struct AdminGuard(pub User);


#[async_trait]
impl<'r> FromRequest<'r> for AuthGuard {
    type Error = AuthError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let cookies = request.cookies();
        let db = request.guard::<Connection<AppDatabase>>().await.unwrap();

        match authorize_user(cookies, db).await {
            Ok(user) => Success(AuthGuard(user)),
            Err(_) => Error((Status::Unauthorized, AuthError::Unauthorized)),
        }
    }          
}

#[async_trait]
impl<'r> FromRequest<'r> for AdminGuard {
    type Error = AuthError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let cookies = request.cookies();
        let db = request.guard::<Connection<AppDatabase>>().await.unwrap();

        match authorize_user(cookies, db).await {
            Ok(user) => {
                if user.is_superuser {
                    Success(AdminGuard(user))
                } else {
                    Error((Status::Forbidden, AuthError::Forbidden))
                }
            },
            Err(_) => Error((Status::Unauthorized, AuthError::Unauthorized)),
        }
    }          
}