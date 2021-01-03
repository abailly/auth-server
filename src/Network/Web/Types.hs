{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Network.Web.Types where

import Data.Aeson
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Proxy
import Crypto.JOSE.JWK
import Data.String (IsString (..))
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import GHC.Generics
import GHC.TypeLits (KnownNat, Nat, natVal)
import Preface.Codec
import Servant.Auth.Server as SAS

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

-- https://www.iana.org/assignments/jwt/jwt.xhtml#claims
-- list of registered claims
-- iss	Issuer	[IESG]	[RFC7519, Section 4.1.1]
-- sub	Subject	[IESG]	[RFC7519, Section 4.1.2]
-- aud	Audience	[IESG]	[RFC7519, Section 4.1.3]
-- exp	Expiration Time	[IESG]	[RFC7519, Section 4.1.4]
-- nbf	Not Before	[IESG]	[RFC7519, Section 4.1.5]
-- iat	Issued At	[IESG]	[RFC7519, Section 4.1.6]
-- jti JWT ID

newtype Bytes (size :: Nat) = Bytes {unBytes :: Encoded Hex}
  deriving (Eq, Show, ToJSON, FromJSON)

instance KnownNat size => IsString (Bytes size) where
  fromString s =
    let e@(Encoded bs) = fromString s
        len = natVal (Proxy @size)
     in if BS.length bs == fromInteger len
          then Bytes e
          else error $ "bytestring should be of length " <> show len <> " but it was " <> show (BS.length bs)

-- | A token ID
newtype TokenID = TokenID {unTokenID :: Bytes 16}
  deriving (Eq, Show, ToJSON, FromJSON, IsString)

-- | A token issued for authenticated users
data AuthenticationToken = AuthToken
  { auID :: Int,
    auOrgID :: Int
  }
  deriving (Eq, Show, Generic)

instance ToJSON AuthenticationToken

instance FromJSON AuthenticationToken

instance ToJWT AuthenticationToken

instance FromJWT AuthenticationToken

-- | A token issued to allow users to register
data RegistrationToken = RegToken
  { -- | The ID of the user who generated this token
    regID :: Int,
    tokID :: TokenID
  }
  deriving (Eq, Show, Generic)

instance ToJSON RegistrationToken

instance FromJSON RegistrationToken

instance ToJWT RegistrationToken

instance FromJWT RegistrationToken

type instance BasicAuthCfg = BasicAuthData -> IO (AuthResult AuthenticationToken)

instance FromBasicAuthData AuthenticationToken where
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
    -- | A Base64-encoded representation of a JWT.
    regToken :: ByteString
  }
  deriving (Eq, Show, Generic)

instance ToJSON UserRegistration where
  toJSON UserRegistration {..} =
    object
      [ "login" .= regLogin,
        "password" .= regPassword,
        "token" .= decodeUtf8 regToken
      ]

instance FromJSON UserRegistration where
  parseJSON = withObject "UserRegistration" $ \obj ->
    UserRegistration <$> obj .: "login" <*> obj .: "password" <*> (encodeUtf8 <$> obj .: "token")

-- | Generate a new random 4096-bits long RSA key pair.
makeNewKey :: IO JWK
makeNewKey = genJWK (RSAGenParam (4096 `div` 8))
