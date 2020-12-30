import Data.Aeson (eitherDecode)
import qualified Data.Text.Lazy as Text
import Data.Text.Lazy.Encoding (encodeUtf8)
import Network.Web.Auth
import System.Environment (lookupEnv)

main :: IO ()
main = do
  key <- getKey <$> lookupEnv "AUTH_SERVER_JWK"
  port <- maybe defaultPort read <$> lookupEnv "AUTH_SERVER_PORT"
  passwords <- lookupEnv "AUTH_SERVER_PASSWORDS"
  startServer (AuthConfig port passwords 5000000 key) >>= waitServer
  where
    getKey Nothing = error "Environment variable AUTH_SERVER_JWK is not set"
    getKey (Just k) = either (error "environment variable 'AUTH_SERVER_JWK' is not set to a valid JWK key: ") id (eitherDecode $ encodeUtf8 $ Text.pack k)
