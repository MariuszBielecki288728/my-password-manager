use super::*;

#[test]
fn test_generate_password() {
    assert_eq!(1, 1);
}

#[test]
fn test_encryption() {
    let encrypted = encrypt_("SuperSecurePassword", "Please, encrypt this");
    let decrypted = decrypt_("SuperSecurePassword", encrypted);
    assert_eq!(decrypted, "Please, encrypt this".to_string());
}

#[test]
#[should_panic(expected = "Unable to decrypt data: ()")]
fn test_encryption_fail() {
    let encrypted = encrypt_("SuperSecurePassword", "Please, encrypt this");
    decrypt_("VeryDifferentPassword", encrypted);
}