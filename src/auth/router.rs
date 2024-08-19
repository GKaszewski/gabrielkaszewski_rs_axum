use rocket::Route;
use rocket::routes;

use super::handlers::{admin, me, login, logout, create_user, get_users};

pub fn routes() -> Vec<Route> {
    routes![
        admin,
        me,
        login,
        logout,
        create_user,
        get_users
    ]
}