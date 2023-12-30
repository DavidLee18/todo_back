// @generated automatically by Diesel CLI.

diesel::table! {
    todos (id) {
        id -> Int4,
        title -> Varchar,
        content -> Varchar,
        completed -> Bool,
        added_date -> Timestamp,
        owner_id -> Int4,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        username -> Varchar,
        password_hash -> Varchar,
        token -> Nullable<Varchar>,
    }
}

diesel::joinable!(todos -> users (owner_id));

diesel::allow_tables_to_appear_in_same_query!(
    todos,
    users,
);
