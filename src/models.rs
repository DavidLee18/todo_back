use std::time::SystemTime;

use diesel::prelude::*;
use serde::{Serialize, Deserialize};

#[derive(Queryable, Selectable, Identifiable, Serialize, Associations)]
#[diesel(table_name = crate::schema::todos)]
#[diesel(belongs_to(User, foreign_key = owner_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Todo {
    pub id: i32,
    pub title: String,
    pub content: String,
    pub completed: bool,
    pub added_date: SystemTime,
    pub owner_id: i32
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = crate::schema::todos)]
pub struct CreateTodo {
    pub title: String,
    pub content: String
}

#[derive(Queryable, Selectable, Identifiable, Clone, Serialize)]
#[diesel(table_name = crate::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password_hash: String,
    pub token: Option<String>
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct CreateUser {
    pub username: String,
    pub password_hash: String
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub exp: usize,
    pub user_id: i32,
}

#[derive(Deserialize)]
pub struct QueryId {
    pub id: i32
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password_hash: String
}