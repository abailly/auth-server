{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DeriveGeneric #-}
module Network.Web.Types where

import Data.Text(Text)
import Data.Aeson
import Data.ByteString (ByteString)
import GHC.Generics
import Servant.Auth.Server as SAS
import Data.Text.Encoding (encodeUtf8, decodeUtf8)

-- Tokens structure from AWS
-- AWS ID Token structure
-- {
-- "sub": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
-- "aud": "xxxxxxxxxxxxexample",
-- "email_verified": true,
-- "token_use": "id",
-- "auth_time": 1500009400,
-- "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
-- "cognito:username": "janedoe",
-- "exp": 1500013000,
-- "given_name": "Jane",
-- "iat": 1500009400,
-- "email": "janedoe@example.com"
-- }

-- AWS Access Token payload

-- {
--     "auth_time": 1500009400,
--     "exp": 1500013000,
--     "iat": 1500009400,
--     "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
--     "scope": "aws.cognito.signin.user.admin",
--     "sub": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
--     "token_use": "access",
--     "username": "janedoe@example.com"
-- }

-- | Dead simple payload attached to JWT
-- TODO: replace with actual payload from auth provider
data AuthenticatedUser = AUser
  { auID :: Int,
    auOrgID :: Int
  }
  deriving (Show, Generic)

instance ToJSON AuthenticatedUser

instance FromJSON AuthenticatedUser

instance ToJWT AuthenticatedUser

instance FromJWT AuthenticatedUser

type instance BasicAuthCfg = BasicAuthData -> IO (AuthResult AuthenticatedUser)

instance FromBasicAuthData AuthenticatedUser where
  fromBasicAuthData authData authCheckFunction = authCheckFunction authData

type Login = ByteString

data Credentials = Credentials
  { credLogin :: Text,
    credPassword :: Text
  }
  deriving (Eq, Show, Generic)

instance ToJSON Credentials

instance FromJSON Credentials

data UserRegistration = UserRegistration
  { regLogin :: Text,
    regPassword :: Text,
    -- |A Base64-encoded representation of a JWT.
    regToken :: ByteString
  }
  deriving (Eq, Show, Generic)

instance ToJSON UserRegistration where
  toJSON UserRegistration{..} =
    object [ "login" .= regLogin,
             "password" .= regPassword,
             "token" .= decodeUtf8 regToken ]

instance FromJSON UserRegistration where
  parseJSON = withObject "UserRegistration" $ \obj ->
    UserRegistration <$> obj .: "login" <*> obj .: "password" <*> (encodeUtf8 <$> obj .: "token")
