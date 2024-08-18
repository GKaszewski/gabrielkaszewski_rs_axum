#[derive(Debug)]
pub enum UserError {
    FailedToCreateUser(AuthError),
    PasswordTooShort,
    PasswordTooWeak,
    DatabaseInsertError,
    NotFound,
}

#[derive(Debug)]
pub enum AuthError {
    FailedToVerifyPassword,
    FailedToHashPassword,
    UserNotFound
}
