from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, TypedDict
from typing_extensions import NotRequired

import extra_streamlit_components as stx
import streamlit as st

from . import util


class User(TypedDict):
    username: str
    email: str
    passhash: str
    expiration: datetime
    valid_from: NotRequired[datetime]


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
        self._users = users
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

        self._users_as_dict: Dict[str, User] = {user["username"]: user for user in self._users}

    # @property
    # def _users_as_dict(self) -> Dict[str, User]:
    #     return {user["username"]: user for user in self._users}

    def _token_encode(self, username: str) -> Tuple[str, datetime]:
        """
        Encodes the contents of the reauthentication cookie.

        Returns
        -------
        str
            The JWT cookie for passwordless reauthentication.
        """
        expiration = self._users_as_dict[username]["expiration"]
        return util.encode_jwt_token(
            username=username,
            days_to_expiry=self.cookie_expiry_days,
            expiry_datetime=expiration,
            secret_key=self.cookie_secret_key,
            jwt_username_field=self.jwt_username_field,
            jwt_expiration_field=self.jwt_expiration_field,
        )

    def _token_decode(self, token: str) -> Dict:
        """
        Decodes the contents of the reauthentication cookie.

        Returns
        -------
        str
            The decoded JWT cookie for passwordless reauthentication.
        """
        return util.decode_jwt_token(token=token, secret_key=self.cookie_secret_key)

    def _check_cookie_auth(self) -> None:
        """
        Checks the validity of the reauthentication cookie.
        """
        token = self.cookie_manager.get(self.cookie_name)

        st.session_state["cookie_auth_response_count"] = (
            st.session_state.get("cookie_auth_response_count", 0) + 1
        )

        if token is not None:
            try:
                decoded_token = self._token_decode(token)
            except Exception as e:
                st.exception(e)
                self.cookie_manager.delete(self.cookie_name)
            else:
                if decoded_token[self.jwt_username_field] not in self._users_as_dict:
                    st.warning("Incorrect username in the cookie")
                    self.cookie_manager.delete(self.cookie_name)
                elif not st.session_state["logout"] and (
                    decoded_token[self.jwt_expiration_field]
                    > datetime.now(tz=timezone.utc).timestamp()
                ):
                    st.session_state["username"] = decoded_token[self.jwt_username_field]
                    st.session_state["authentication_status"] = True
            st.session_state["is_cookie_auth_done"] = True
        else:
            if st.session_state["cookie_auth_response_count"] > 1:
                st.session_state["is_cookie_auth_done"] = True

    def _check_pw_auth(self, username: str, password: str) -> None:
        """
        Checks the validity of the entered credentials.
        """
        if username not in self._users_as_dict:
            success, message = False, "Credentials are incorrect"
        else:
            success, message = util.verify_password(
                submitted_password=password,
                expected_hash=self._users_as_dict[username]["passhash"],
                expiration=self._users_as_dict[username]["expiration"],
                valid_from=self._users_as_dict[username].get("valid_from"),
            )
        if not success:
            st.warning(message)
            st.session_state["authentication_status"] = False
        else:
            token, token_expiry = self._token_encode(username)
            self.cookie_manager.set(
                self.cookie_name,
                token,
                expires_at=token_expiry,
            )
            st.session_state["authentication_status"] = True

    def _is_cookie_auth_done(self) -> bool:
        """
        Returns true if the authentication cookie has been loaded.
        """
        return st.session_state.get("is_cookie_auth_done", False)

    def _is_authenticated(self) -> Optional[bool]:
        """
        Returns true if the user is authenticated, false otherwise.
        Returns None if the authentication cookie is still loading.
        """

        return st.session_state.get("authentication_status", None)

    def login(
        self,
        form_name: str,
        location: str = "main",
        checkbox_labels: Optional[List[str]] = None,
        markdown_texts: Optional[List[str]] = None,
    ) -> Tuple[Optional[bool], str, Optional[datetime]]:
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
            The status of authentication:
                True - the user is authenticated
                False - incorrect / no credentials or cookie provided
                None - the authentication cookie is still loading
        str
            Username of the authenticated user.
        """

        if not self._is_authenticated():
            # If not authenticated, check the cookie; if the authentication cookie exists,
            # authenticate the user
            self._check_cookie_auth()
            if not self._is_cookie_auth_done():
                # If the cookie is still loading, show a loading view
                st.write("Loading...")
            elif not self._is_authenticated():
                # If the cookie is done loading but the user is not authenticated,
                # show the login form
                if location == "main":
                    login_form = st.form("Login")
                elif location == "sidebar":
                    login_form = st.sidebar.form("Login")
                else:
                    raise ValueError("Location must be one of 'main' or 'sidebar'")
                login_form.subheader(form_name)
                username = login_form.text_input("Username").lower()
                password = login_form.text_input("Password", type="password")
                if checkbox_labels is not None:
                    checkboxes = []
                    for checkbox_label in checkbox_labels:
                        checkboxes.append(login_form.checkbox(checkbox_label))
                if markdown_texts is not None:
                    for markdown_text in markdown_texts:
                        login_form.markdown(markdown_text)

                # Check submitted username and password
                if login_form.form_submit_button("Login"):
                    # The user must accept all the terms and conditions,
                    if all(checkboxes):
                        st.session_state["username"] = username
                        # If the submitted credentials are correct, authenticate the user
                        self._check_pw_auth(username, password)
                    else:
                        st.warning("Please accept the terms and conditions")
                        st.session_state["authentication_status"] = False
                else:
                    st.session_state["authentication_status"] = False

        # When authentication process is done, authentication status and username
        # are stored in the session state
        username = st.session_state["username"]
        expiration = (
            self._users_as_dict[username]["expiration"] if self._is_authenticated() else None
        )
        return (
            self._is_authenticated(),
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
