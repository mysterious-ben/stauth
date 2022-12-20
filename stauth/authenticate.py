from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, TypedDict

import jwt
import bcrypt
import streamlit as st
import extra_streamlit_components as stx


class User(TypedDict):
    username: str
    email: str
    passhash: str
    expiration: datetime


class Authenticate:
    """
    This class will create login and logout widgets.
    """

    def __init__(
        self,
        users: List[User],
        cookie_name: str,
        cookie_secret_key: str,
        cookie_expiry_days: int,
        jwt_username_field: str = "role",
        jwt_expiration_field: str = "exp",
    ):
        """
        Create a new instance of "Authenticate".

        Parameters
        ----------
        credentials: dict
            The dictionary of usernames, names, passwords, and emails.
        cookie_name: str
            The name of the JWT cookie stored on the client's browser for passwordless
            reauthentication.
        key: str
            The key to be used for hashing the signature of the JWT cookie.
        cookie_expiry_days: int
            The number of days before the cookie expires on the client's browser.
        """
        self.users = users
        self.cookie_name = cookie_name
        self.cookie_secret_key = cookie_secret_key
        self.cookie_expiry_days = cookie_expiry_days
        self.jwt_username_field = jwt_username_field
        self.jwt_expiration_field = jwt_expiration_field
        self.cookie_manager = stx.CookieManager()

        if "authentication_status" not in st.session_state:
            st.session_state["authentication_status"] = None
        if "username" not in st.session_state:
            st.session_state["username"] = None
        if "logout" not in st.session_state:
            st.session_state["logout"] = None

    @property
    def users_as_dict(self) -> Dict[str, User]:
        return {user["username"]: user for user in self.users}

    def _token_encode(self, username: str, exp_timestamp: float) -> str:
        """
        Encodes the contents of the reauthentication cookie.

        Returns
        -------
        str
            The JWT cookie for passwordless reauthentication.
        """
        token = jwt.encode(
            payload={
                self.jwt_username_field: username,
                self.jwt_expiration_field: exp_timestamp,
            },
            key=self.cookie_secret_key,
            algorithm="HS256",
        )
        return token

    def _token_decode(self, token: str) -> Dict:
        """
        Decodes the contents of the reauthentication cookie.

        Returns
        -------
        str
            The decoded JWT cookie for passwordless reauthentication.
        """
        return jwt.decode(token, self.cookie_secret_key, algorithms=["HS256"])

    def _get_exp_datetime(self, username: str) -> datetime:
        """
        Creates the reauthentication cookie's expiry date.

        Returns
        -------
        str
            The JWT cookie's expiry timestamp in Unix epoch.
        """
        exp_date = datetime.utcnow() + timedelta(days=self.cookie_expiry_days)
        return min(exp_date, self.users_as_dict[username]["expiration"])

    def _check_pw(self, username: str, password: str) -> bool:
        """
        Checks the validity of the entered password.

        Returns
        -------
        bool
            The validity of the entered password by comparing it to the hashed password on disk.
        """
        return bcrypt.checkpw(
            password.encode(),
            self.users_as_dict[username]["passhash"].encode(),
        )

    def _check_cookie_auth(self) -> None:
        """
        Checks the validity of the reauthentication cookie.
        """
        token = self.cookie_manager.get(self.cookie_name)
        if token is not None:
            try:
                decoded_token = self._token_decode(token)
            except Exception as e:
                st.exception(e)
            else:
                if (
                    not st.session_state["logout"]
                    and decoded_token[self.jwt_expiration_field]
                    > datetime.utcnow().timestamp()
                ):
                    st.session_state["username"] = decoded_token[self.jwt_username_field]
                    st.session_state["authentication_status"] = True

    def _check_pw_auth(self, username: str, password: str) -> None:
        """
        Checks the validity of the entered credentials.
        """
        if (username in self.users_as_dict) and self._check_pw(username, password):
            if self.users_as_dict[username]["expiration"] > datetime.utcnow():
                exp_datetime = self._get_exp_datetime(username)
                token = self._token_encode(username, exp_datetime.timestamp())
                self.cookie_manager.set(
                    self.cookie_name,
                    token,
                    expires_at=exp_datetime,
                )
                st.session_state["authentication_status"] = True
            else:
                st.warning("Username/Password have expired")
                st.session_state["authentication_status"] = False
        else:
            st.warning("Username/Password are incorrect")
            st.session_state["authentication_status"] = False

    def login(
        self, form_name: str, location: str = "main"
    ) -> Tuple[bool, str, Optional[datetime]]:
        """
        Creates a login widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the login form.
        location: str
            The location of the login form i.e. main or sidebar.
        Returns
        -------
        str
            Name of the authenticated user.
        bool
            The status of authentication, None: no credentials entered,
            False: incorrect credentials, True: correct credentials.
        str
            Username of the authenticated user.
        """
        if not st.session_state["authentication_status"]:
            self._check_cookie_auth()
            if not st.session_state["authentication_status"]:
                if location == "main":
                    login_form = st.form("Login")
                elif location == "sidebar":
                    login_form = st.sidebar.form("Login")
                else:
                    raise ValueError("Location must be one of 'main' or 'sidebar'")
                login_form.subheader(form_name)
                username = login_form.text_input("Username").lower()
                password = login_form.text_input("Password", type="password")
                if login_form.form_submit_button("Login"):
                    st.session_state["username"] = username
                    self._check_pw_auth(username, password)

        username = st.session_state["username"]
        expiration = (
            self.users_as_dict[username]["expiration"] if username in self.users_as_dict else None
        )
        return (
            st.session_state["authentication_status"],
            username,
            expiration,
        )

    def logout(self, button_name: str, location: str = "main"):
        """
        Creates a logout button.

        Parameters
        ----------
        button_name: str
            The rendered name of the logout button.
        location: str
            The location of the logout button i.e. main or sidebar.
        """
        if location == "main":
            logout_button = st.button(button_name)
        elif location == "sidebar":
            logout_button = st.sidebar.button(button_name)
        if logout_button:
            self.cookie_manager.delete(self.cookie_name)
            st.session_state["logout"] = True
            st.session_state["username"] = None
            st.session_state["authentication_status"] = None
