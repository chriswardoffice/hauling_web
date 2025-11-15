use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};

fn main() {
    let password = b"mypassword123"; // Replace with your actual password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password, &salt).unwrap().to_string();
    println!("{}", hash); // Copy this for ADMIN_PASSWORD_HASH
}
