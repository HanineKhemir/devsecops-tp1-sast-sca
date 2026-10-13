from werkzeug.security import check_password_hash, generate_password_hash


def hash_password(password):
    # pbkdf2:sha256 with per-user salt, replaces the previous insecure MD5.
    return generate_password_hash(password)


def verify_password(stored_hash, candidate):
    return check_password_hash(stored_hash, candidate)
