use axum::{
    extract::{State, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use deadpool_diesel::postgres::Pool;
use diesel::{QueryDsl, IntoSql, ExpressionMethods, RunQueryDsl, SelectableHelper};

use crate::models::User;

pub async fn require_authentication(
    State(pool): State<Pool>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let header_token = headers.get("x-auth-token")
        .ok_or((
            StatusCode::UNAUTHORIZED,
            String::from("not authenticated!"),
        ))
        .map(|t| t.to_str().map_err(|error| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Error extracting token from headers: {:?}", error))
        }))??;

    let conn = pool.get().await.map_err(crate::internal_error)?;

    let token_secret = std::env::var("JWT_SECRET").map_err(crate::internal_error)?;

    let user_id = crate::verify_token(&token_secret, header_token)?;

    use crate::schema::users::dsl::*;
    use diesel::OptionalExtension;

    let user: Option<User> = conn.interact(move |conn| users.filter(id.eq(user_id))
        .first(conn)
        .optional()
    ).await
        .map_err(crate::internal_error)?
        .map_err(crate::internal_error)?;

    let u = user.ok_or((
        StatusCode::UNAUTHORIZED,
        String::from("You are not authorized for this"),
    ))?;
    request.extensions_mut().insert(u);

    Ok(next.run(request).await)
}