from datetime import datetime, timezone

import bcrypt
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

st.session_state["session_run"] = st.session_state.get("session_run", 0) + 1
session_run = st.session_state["session_run"]

print(f"rendering started {session_run=}")

authenticator = Authenticate(
    users=users,  # type: ignore
    cookie_name="auth_login_cookie",
    cookie_secret_key="hereisverysercretkey",
    cookie_expiry_days=5,
)
print(f"authenticator created {session_run=}")

st.title("The Streamlit App")
authentication_status, username, expiration = authenticator.loading_view()

if authenticator.is_cookie_auth_done():

    if not authentication_status:
        authentication_status, username, expiration = authenticator.login(
            "Login",
            "main",
            checkbox_labels=[
                "I accept Terms and Conditions*",
                "I accept that this website uses functional cookies",
            ],
            markdown_texts=["Trademark Green Outer Space TM"]
        )
        print(f"login rendered {session_run=}")

    if authentication_status is True:
        print(f"authorized {session_run=}")
        assert expiration is not None
        st.markdown(f"Success! Logged in as '{username}'.")
        st.markdown(f"The credentials will expire on '{expiration.isoformat()}'.")
        authenticator.logout("Logout")
        print(f"logout rendered {session_run=}")
    else:
        pass

print(f"page rendered: {username=} {authentication_status=} {expiration=} {session_run=}")
