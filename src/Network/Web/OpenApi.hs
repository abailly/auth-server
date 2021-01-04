{-# LANGUAGE TypeApplications #-}

module Network.Web.OpenApi (authSwagger, Swagger) where

import Control.Lens
import Data.Proxy
import Data.Swagger hiding (Reference)
import Data.Text (pack)
import Network.Web.API
import Network.Web.Types
import Network.Web.Version
import Servant.Auth.Swagger ()
import Servant.Swagger

instance ToSchema Credentials

instance ToSchema UserRegistration

instance ToSchema SerializedToken where
  declareNamedSchema _ =
    return $
      NamedSchema (Just "SerializedToken") $
        mempty
          & description
            ?~ "A JWT Token in its serialized form, eg. 3 sequneces of base64-encoded strings separated by dots \
               \ which contain JSON objects. See https://jwt.io/introduction for more details."
          & type_ ?~ SwaggerString

authSwagger :: Swagger
authSwagger =
  toSwagger (Proxy @AuthAPIServer)
    & info . title .~ "Authentication Server API"
    & info . version .~ pack (showVersion authVersion)
    & info . description ?~ "An API for managing REST services authentication and basic user credentials."
    & info . license ?~ "All Rights Reserveγd"
