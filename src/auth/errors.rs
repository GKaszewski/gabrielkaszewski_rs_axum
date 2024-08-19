#[derive(Debug)]
pub enum UserError {
    FailedToCreateUser(AuthError),
    PasswordTooShort,
    PasswordTooWeak,
    DatabaseInsertError,
    NotFound,
}

pub enum JWTError {
    FailedToCreateToken,
    FailedToDecodeToken,
}

#[derive(Debug)]
pub enum AuthError {
    FailedToVerifyPassword,
    FailedToHashPassword,
    UserNotFound,
    FailedToGenerateToken,
    FailedToAuthorize,
    NoAuthTokenCookie,
    Unauthorized,
    Forbidden,
}
