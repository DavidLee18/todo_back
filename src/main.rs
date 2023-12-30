pub mod models;
pub mod schema;

use std::{collections::HashMap, env, time::Duration};

use crate::models::Todo;
use axum::{Router, Json, http::{StatusCode, Request}, extract::{State, Query}, routing::put, response::Response};
use deadpool_diesel::postgres::Pool;
use diesel::{SelectableHelper, RunQueryDsl, QueryDsl, ExpressionMethods};
use jsonwebtoken as jwt;
use models::{CreateTodo, Claims};
use tower_http::{trace::TraceLayer, classify::ServerErrorsFailureClass};
use tracing::Span;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::{OpenApi, Modify, openapi::security::{SecurityScheme, ApiKey, ApiKeyValue}};
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
    paths(
        get_todos,
        create_todo,
        complete_todo,
        delete_todo,
    ),
    components(
        schemas(Todo, CreateTodo)
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "todo", description = "Todo items management API")
    )
)]
struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("todo_apikey"))),
            )
        }
    }
}

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
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route(
            "/",
            put(create_todo)
            .get(get_todos)
            .post(complete_todo)
            .delete(delete_todo),
        )
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

#[utoipa::path(put, path="/", request_body = CreateTodo, responses(
    (status = 201, body = Todo)
))]
async fn create_todo(State(pool): State<Pool>, Json(todo): Json<CreateTodo>) -> Result<(StatusCode, Json<Todo>), (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

    use crate::schema::todos;

    let res = conn.interact(move |conn| 
        diesel::insert_into(todos::table)
        .values(&todo)
        .returning(Todo::as_returning())
        .get_result(conn)
    ).await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    Ok((StatusCode::CREATED, Json(res)))
}

#[utoipa::path(get, path="/", responses(
    (status = 200, body = [Todo])
))]
async fn get_todos(State(pool): State<Pool>) -> Result<(StatusCode, Json<Vec<Todo>>), (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

    use crate::schema::todos::dsl::*;

    let res = conn.interact(move |conn| 
        todos
        .select(Todo::as_select())
        .load(conn)
    ).await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    Ok((StatusCode::OK, Json(res)))
}

#[utoipa::path(post, path="/", params(("id" = String, Query,)), responses(
    (status = 200, body = Todo)
))]
async fn complete_todo(State(pool): State<Pool>, Query(params): Query<HashMap<String, i32>>) -> Result<Json<Todo>, (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;
    let req_id = *params.get("id").ok_or((StatusCode::INTERNAL_SERVER_ERROR, "no param named \"id\".".to_string()))?;

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

#[utoipa::path(delete, path="/", params(("id" = String, Query,)), responses(
    (status = 200)
))]
async fn delete_todo(State(pool): State<Pool>, Query(params): Query<HashMap<String, i32>>) -> Result<(), (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;
    let req_id = *params.get("id").ok_or((StatusCode::INTERNAL_SERVER_ERROR, "no param named \"id\".".to_string()))?;

    use crate::schema::todos::dsl::*;

    let _ = conn.interact(move |conn| 
        diesel::delete(todos.find(req_id))
        .execute(conn)
    ).await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    Ok(())
}

/// Utility function for mapping any error into a `500 Internal Server Error`
/// response.
fn internal_error<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

fn create_token(secret: &str, username: String) -> Result<String, (StatusCode, String)> {
    let claims = Claims { username, exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize };
    let key = jwt::EncodingKey::from_secret(secret.as_bytes());

    jwt::encode(&jwt::Header::default(), &claims, &key)
        .map_err(internal_error)

}

fn verify_token(secret: &str, token: &str) -> Result<bool, (StatusCode, String)> {
    unimplemented!()
}