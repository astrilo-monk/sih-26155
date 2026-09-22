"""DATABASE_URL handling: a raw dashboard password with @ or $ still names the right host."""

from app.db.database import _encode_password


def test_raw_password_is_encoded_and_an_encoded_one_is_left_alone():
    assert (_encode_password("postgresql://u.p:ab@c$$@h.example:5432/postgres")
            == "postgresql://u.p:ab%40c%24%24@h.example:5432/postgres")
    assert _encode_password("postgresql://u.p:ab%40c@h:5432/db") == "postgresql://u.p:ab%40c@h:5432/db"
    assert _encode_password("") == ""
