use argon2::{
    password_hash::{rand_core::OsRng, PasswordHashString, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use hmac::{Hmac, Mac};
use jwt::{RegisteredClaims, SignWithKey, VerifyWithKey};
use rocket::http::CookieJar;
use rocket_db_pools::Connection;
use sha2::Sha512;

use crate::db::AppDatabase;

use super::{
    errors::{AuthError, JWTError, UserError},
    models::{LoginData, User, UserData, UserRead},
    utils::parse_duration_from_string,
};

pub struct UserBuilder {
    username: String,
    password: String,
    is_superuser: bool,
}

impl UserBuilder {
    pub fn new() -> Self {
        UserBuilder {
            username: "".to_string(),
            password: "".to_string(),
            is_superuser: false,
        }
    }

    pub fn username(mut self, username: String) -> Self {
        self.username = username;
        self
    }

    pub fn password(mut self, password: String) -> Self {
        self.password = password;
        self
    }

    pub fn is_superuser(mut self, is_superuser: bool) -> Self {
        self.is_superuser = is_superuser;
        self
    }

    pub fn build(self) -> User {
        User {
            id: 0,
            username: self.username,
            password: self.password,
            is_superuser: self.is_superuser,
            created_at: chrono::Utc::now().naive_utc(),
            updated_at: chrono::Utc::now().naive_utc(),
        }
    }
}

fn check_password_strength(password: &str) -> Result<(), UserError> {
    if password.len() < 8 {
        return Err(UserError::PasswordTooShort);
    }

    // check if password contains at least one uppercase letter
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(UserError::PasswordTooWeak);
    }

    // check if password contains at least one lowercase letter
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(UserError::PasswordTooWeak);
    }

    // check if password contains at least one digit
    if !password.chars().any(|c| c.is_numeric()) {
        return Err(UserError::PasswordTooWeak);
    }

    let special_characters = "!@#$%^&*()-_+=[]{}|;:,.<>?".chars().collect::<Vec<char>>();
    // check if password contains at least one special character

    if !password.chars().any(|c| special_characters.contains(&c)) {
        return Err(UserError::PasswordTooWeak);
    }

    Ok(())
}

pub fn hash_password(password: &str) -> Result<PasswordHashString, AuthError> {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AuthError::FailedToHashPassword)?;
    Ok(hashed_password.serialize())
}

pub fn verify_password(hashed_password: &PasswordHash, password: String) -> Result<(), AuthError> {
    let algs: &[&dyn PasswordVerifier] = &[&Argon2::default()];

    hashed_password
        .verify_password(algs, password)
        .map_err(|_| AuthError::FailedToVerifyPassword)
}

pub fn generate_jwt_token(user: User) -> Result<String, JWTError> {
    let key = std::env::var("JWT_SECRET").unwrap_or_else(|_| "secret".to_string());
    let encrypted_key: Hmac<Sha512> =
        Hmac::new_from_slice(key.as_bytes()).map_err(|_| JWTError::FailedToCreateToken)?;
    let expiration_string = parse_duration_from_string(
        std::env::var("JWT_EXPIRATION")
            .unwrap_or_else(|_| "1d".to_string())
            .as_str(),
    )
    .map_err(|_| JWTError::FailedToCreateToken)?;

    let expiration = chrono::Utc::now() + expiration_string;
    let claims = RegisteredClaims {
        issuer: Some("gabrielkaszewski-auth".to_string()),
        subject: Some(user.username),
        expiration: Some(expiration.timestamp() as u64),
        not_before: Some(chrono::Utc::now().timestamp() as u64),
        issued_at: Some(chrono::Utc::now().timestamp() as u64),
        ..Default::default()
    };

    let token_string = claims
        .sign_with_key(&encrypted_key)
        .map_err(|_| JWTError::FailedToCreateToken)?;

    Ok(token_string)
}

pub fn create_user(data: UserData) -> Result<User, UserError> {
    let mut user = User::builder()
        .username(data.username.to_string())
        .password(data.password.to_string())
        .is_superuser(data.is_superuser)
        .build();

    let password = user.password.clone();
    if let Err(e) = check_password_strength(&password) {
        return Err(e);
    }

    // hash the password
    let hashed_password = hash_password(&password).map_err(UserError::FailedToCreateUser)?;
    user.password = hashed_password.to_string();

    Ok(user)
}

pub async fn save_user(user: User, mut db: Connection<AppDatabase>) -> Result<User, UserError> {
    sqlx::query!(
        r#"
        INSERT INTO users (username, password, is_superuser, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        user.username,
        user.password,
        user.is_superuser,
        user.created_at,
        user.updated_at
    )
    .execute(&mut **db)
    .await
    .map_err(|_| UserError::DatabaseInsertError)?;

    Ok(user)
}

pub async fn get_users(mut db: Connection<AppDatabase>) -> Result<Vec<UserRead>, UserError> {
    let users = sqlx::query_as!(
        User,
        r#"
        SELECT * FROM users
        "#
    )
    .fetch_all(&mut **db)
    .await
    .map_err(|_| UserError::DatabaseInsertError)?;

    let users = users
        .into_iter()
        .map(|user| UserRead {
            id: user.id,
            username: user.username,
            is_superuser: user.is_superuser,
            created_at: user.created_at,
            updated_at: user.updated_at,
        })
        .collect();

    Ok(users)
}

pub async fn get_user_by_username(
    username: &str,
    mut db: Connection<AppDatabase>,
) -> Result<User, UserError> {
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT * FROM users WHERE username = $1
        "#,
        username
    )
    .fetch_one(&mut **db)
    .await
    .map_err(|_| UserError::NotFound)?;

    Ok(user)
}

pub async fn login<'r>(
    user_data: LoginData,
    db: Connection<AppDatabase>,
    cookie_jar: &'r CookieJar<'_>,
) -> Result<(), AuthError> {
    let username = user_data.username;
    let password = user_data.password;

    let user = get_user_by_username(&username, db)
        .await
        .map_err(|_| AuthError::UserNotFound)?;

    let hashed_password =
        PasswordHash::new(&user.password).map_err(|_| AuthError::FailedToVerifyPassword)?;

    verify_password(&hashed_password, password).map_err(|_| AuthError::FailedToVerifyPassword)?;

    let token = generate_jwt_token(user).map_err(|_| AuthError::FailedToGenerateToken)?;

    cookie_jar.add_private(("auth_token", token));

    Ok(())
}

pub fn logout<'r>(cookie_jar: &CookieJar<'_>) {
    cookie_jar.remove_private("auth_token");
}

pub async fn authorize_user<'r>(
    cookie_jar: &'r CookieJar<'_>,
    db: Connection<AppDatabase>,
) -> Result<User, AuthError> {
    let key = std::env::var("JWT_SECRET").unwrap_or_else(|_| "secret".to_string());
    let encrypted_key: Hmac<Sha512> =
        Hmac::new_from_slice(key.as_bytes()).map_err(|_| AuthError::FailedToAuthorize)?;
    let token = cookie_jar
        .get_private("auth_token")
        .ok_or(AuthError::NoAuthTokenCookie)?
        .value()
        .to_string();
    let claims: RegisteredClaims = token
        .verify_with_key(&encrypted_key)
        .map_err(|_| AuthError::FailedToAuthorize)?;

    let username = claims.subject.ok_or(AuthError::FailedToAuthorize)?;
    let user = get_user_by_username(&username, db)
        .await
        .map_err(|_| AuthError::FailedToAuthorize)?;

    Ok(user)
}
