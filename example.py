import bcrypt
from datetime import datetime, timezone

import streamlit as st

from stauth.authenticate import Authenticate

user1_password = "1111"
user2_password = "2222"

users = [
    {
        "username": "user1",
        "email": "user1@email.com",
        "passhash": bcrypt.hashpw(user1_password.encode(), bcrypt.gensalt()).decode(),
        "expiration": datetime(2050, 1, 1, tzinfo=timezone.utc),
        "valid_from": datetime(2000, 1, 1, tzinfo=timezone.utc),
    },
    {
        "username": "user2",
        "email": "user2@email.com",
        "passhash": bcrypt.hashpw(user2_password.encode(), bcrypt.gensalt()).decode(),
        "expiration": datetime(2050, 1, 1, tzinfo=timezone.utc),
        "valid_from": datetime(2000, 1, 1, tzinfo=timezone.utc),
    },
]


authenticator = Authenticate(
    users=users,  # type: ignore
    cookie_name="auth_login_cookie",
    cookie_secret_key="hereisverysercretkey",
    cookie_expiry_days=5,
)


st.title("The Streamlit App")
authentication_status, username, expiration = authenticator.login(
    "Login",
    "main",
    [
        "I accept the terms and conditions",
        "I accept that this website uses functional cookies",
    ],
)
if authentication_status is True:
    assert expiration is not None
    st.markdown(f"Success! Logged in as '{username}'.")
    st.markdown(f"The credentials will expire on '{expiration.isoformat()}'.")
    authenticator.logout("Logout")
else:
    pass
