import os

class Config:
    """Application configuration class"""
    def __init__(self):
        # Flask settings
        self.FLASK_SECRET_KEY = self._require_env('FLASK_SECRET_KEY')
        self.FLASK_PORT = int(os.getenv('FLASK_PORT', '3000'))
        self.FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'

        # Keycloak settings
        self.KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'http://localhost:8080')
        self.KEYCLOAK_REALM = self._require_env('REALM')
        self.KEYCLOAK_CLIENT_ID = self._require_env('CLIENT_ID')
        self.KEYCLOAK_CLIENT_SECRET = self._require_env('CLIENT_SECRET')
        self.KEYCLOAK_REDIRECT_URI = os.getenv('REDIRECT_URI', 'http://localhost:3000/callback')

        # Derived URLs
        self.KEYCLOAK_AUTH_URL = f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}/protocol/openid-connect/auth"
        self.KEYCLOAK_TOKEN_URL = f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}/protocol/openid-connect/token"
        self.KEYCLOAK_USERINFO_URL = f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
        self.KEYCLOAK_JWKS_URL = f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}/protocol/openid-connect/certs"

    def _require_env(self, name: str) -> str:
        """Get a required environment variable or raise an error"""
        value = os.getenv(name)
        if value is None:
            raise ValueError(f"Missing required environment variable: {name}")
        return value 