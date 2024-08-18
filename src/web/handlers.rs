use askama_rocket::Template;
use rocket::get;

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {}

#[get("/")]
pub fn index() -> IndexTemplate {
    IndexTemplate {}
}
