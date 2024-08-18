use argon2::{
    password_hash::{rand_core::OsRng, PasswordHashString, Salt, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier, RECOMMENDED_SALT_LEN,
};
use rocket_db_pools::Connection;

use crate::db::AppDatabase;

use super::{
    errors::{AuthError, UserError},
    models::{LoginData, User, UserData, UserRead},
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

pub async fn login(user_data: LoginData, db: Connection<AppDatabase>) -> Result<(), AuthError> {
    let username = user_data.username;
    let password = user_data.password;

    let user = get_user_by_username(&username, db)
        .await
        .map_err(|_| AuthError::UserNotFound)?;

    let hashed_password =
        PasswordHash::new(&user.password).map_err(|_| AuthError::FailedToVerifyPassword)?;

    verify_password(&hashed_password, password)
}
