pub mod models;
pub mod schema;
pub mod middleware;

use std::{env, time::Duration};

use crate::models::Todo;
use axum::{Router, Json, http::{StatusCode, Request}, extract::{State, Query}, routing::{put, delete, post, get}, response::Response, middleware::from_fn_with_state, Extension};
use deadpool_diesel::postgres::Pool;
use diesel::{SelectableHelper, RunQueryDsl, QueryDsl, ExpressionMethods, BoolExpressionMethods};
use jsonwebtoken as jwt;
use models::{CreateTodo, Claims, User, QueryId, CreateUser, LoginForm};
use tower_http::{trace::TraceLayer, classify::ServerErrorsFailureClass};
use tracing::Span;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().expect("reading .env file failed");

    // set up connection pool
    let manager = deadpool_diesel::postgres::Manager::new(env::var("DATABASE_URL").expect("DATABASE_URL must be set"), deadpool_diesel::Runtime::Tokio1);
    let pool = Pool::builder(manager).build().unwrap();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    // build our application with some routes
    let app = Router::new()
        .route(
            "/todo",
            put(create_todo)
            .get(get_todos)
            .post(complete_todo)
            .delete(delete_todo),
        )
        .route("/users", delete(delete_user))
        .route("/users/change_password", post(change_password))
        .route("/users/logout", get(logout))
        .layer(from_fn_with_state(pool.clone(), crate::middleware::require_authentication))
        .route("/users", put(create_user).get(get_users))
        .route("/users/login", post(login))
        .layer(
            TraceLayer::new_for_http()
                .on_request(|req: &Request<_>, _span: &Span| {
                    tracing::info!("{} {}", req.method(), req.uri());
                })
                .on_response(|res: &Response, _latency: Duration, _span: &Span| {
                    tracing::info!("{}", res.status());
                })
                .on_failure(|error: ServerErrorsFailureClass, _latency: Duration, _span: &Span| {
                    tracing::error!("{}", error);
                })
        )
        .with_state(pool);

    // run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app.into_make_service()).await.unwrap();
}

// todo CRUD

async fn create_todo(
    State(pool): State<Pool>,
    Extension(user): Extension<User>,
    Json(todo): Json<CreateTodo>,
) -> Result<(StatusCode, Json<Todo>), (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

    use crate::schema::todos::dsl::*;

    let res = conn.interact(move |conn| 

        diesel::insert_into(todos)
        .values((title.eq(todo.title), content.eq(todo.content), owner_id.eq(user.id)))
        .returning(Todo::as_returning())
        .get_result(conn)
    ).await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    Ok((StatusCode::CREATED, Json(res)))
}

async fn get_todos(
    State(pool): State<Pool>,
    Extension(user): Extension<User>
) -> Result<(StatusCode, Json<Vec<Todo>>), (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

    use crate::schema::todos::dsl::*;

    let res = conn.interact(move |conn| 
        todos
        .filter(owner_id.eq(user.id))
        .select(Todo::as_select())
        .load(conn)
    ).await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    Ok((StatusCode::OK, Json(res)))
}

async fn complete_todo(
    State(pool): State<Pool>,
    Extension(_user): Extension<User>,
    Query(QueryId { id: req_id }): Query<QueryId>
) -> Result<Json<Todo>, (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

    use crate::schema::todos::dsl::*;

    let res = conn.interact(move |conn| 
        diesel::update(todos.find(req_id))
        .set(completed.eq(true))
        .returning(Todo::as_returning())
        .get_result(conn)
    ).await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    Ok(Json(res))
}

async fn delete_todo(
    State(pool): State<Pool>,
    Extension(_user): Extension<User>,
    Query(QueryId { id: req_id }): Query<QueryId>
) -> Result<(), (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

    use crate::schema::todos::dsl::*;

    let _ = conn.interact(move |conn| 
        diesel::delete(todos.find(req_id))
        .execute(conn)
    ).await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    Ok(())
}

async fn create_user(
    State(pool): State<Pool>,
    Json(user): Json<CreateUser>
) -> Result<(StatusCode, Json<User>), (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

    use schema::users::dsl::*;

    let res_user = conn.interact(move |conn| 
        diesel::insert_into(users)
            .values(&user)
            .returning(User::as_returning())
            .get_result(conn)
    ).await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    Ok((StatusCode::CREATED, Json(res_user)))
}

async fn login(
    State(pool): State<Pool>,
    Json(form): Json<LoginForm>
) -> Result<String, (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

    use schema::users::dsl::*;
    use diesel::OptionalExtension;

    let user: User = conn.interact(|conn| 
        users.filter(username.eq(form.username).and(password_hash.eq(form.password_hash)))
            .select(User::as_select())
            .first(conn)
            .optional()
    ).await
    .map_err(internal_error)?
    .map_err(internal_error)?
    .ok_or((StatusCode::UNAUTHORIZED, String::from("no user with specified username and password matched")))?;

    let t = create_token(&env::var("JWT_SECRET").expect("loading .env file failed"), user.id)?;

    let t2 = t.clone();

    let _ = conn.interact(move |conn|
        diesel::update(users.find(user.id))
            .set(token.eq(Some(t)))
            .execute(conn)
    ).await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    Ok(t2)
}

async fn change_password(
    State(pool): State<Pool>,
    Extension(user): Extension<User>,
    Json(new_pw_hash): Json<String>
) -> Result<(), (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

    use schema::users::dsl::*;

    let _ = conn.interact(move |conn|
        diesel::update(users.find(user.id))
            .set((password_hash.eq(new_pw_hash), token.eq::<Option<String>>(None)))
            .execute(conn)
    ).await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    Ok(())
}

async fn logout(
    State(pool): State<Pool>,
    Extension(user): Extension<User>
) -> Result<(), (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

    use schema::users::dsl::*;

    let _ = conn.interact(move |conn|
        diesel::update(users.find(user.id))
            .set(token.eq::<Option<String>>(None))
            .execute(conn)
    ).await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    Ok(())
}

async fn delete_user(
    State(pool): State<Pool>,
    Extension(user): Extension<User>
) -> Result<(), (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

    use schema::users::dsl::*;

    let _ = conn.interact(move |conn|
        diesel::delete(users.find(user.id))
            .execute(conn)
    ).await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    Ok(())
}

async fn get_users(
    State(pool): State<Pool>
) -> Result<Json<Vec<User>>, (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

    use schema::users::dsl::*;

    let mut res_users = conn.interact(|conn|
        users
            .select(User::as_select())
            .get_results(conn)
    ).await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    for u in &mut res_users {
        if let Some(t) = &mut u.token {
            *t = t.chars().map(|_| '*').collect();
        }
    }

    Ok(Json(res_users))
}

/// Utility function for mapping any error into a `500 Internal Server Error`
/// response.
pub fn internal_error<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

pub fn create_token(secret: &str, user_id: i32) -> Result<String, (StatusCode, String)> {
    let claims = Claims { user_id, exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize };
    let key = jwt::EncodingKey::from_secret(secret.as_bytes());

    jwt::encode(&jwt::Header::default(), &claims, &key)
        .map_err(internal_error)

}

pub fn verify_token(secret: &str, token: &str) -> Result<i32, (StatusCode, String)> {
    let key = jwt::DecodingKey::from_secret(secret.as_bytes());
    let validation = jwt::Validation::new(jwt::Algorithm::HS256);
    match jwt::decode::<Claims>(token, &key, &validation) {
            Ok(claim) => Ok(claim.claims.user_id),
            Err(error) => match error.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken
                | jsonwebtoken::errors::ErrorKind::InvalidSignature
                | jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    Err((StatusCode::UNAUTHORIZED, String::from("not authenticated!")))
                },
                _ => {
                    Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Error validating token: {:?}", error)))
                }
            }
        }
}