{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}

module Network.Web.AuthSpec where

import Control.Concurrent (threadDelay)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Control.Exception (IOException, bracket, catch)
import Crypto.JOSE
import Data.Aeson (encode, decode)
import Control.Lens((^.))
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import Network.HTTP.Client
  ( Manager,
    RequestBody (RequestBodyLBS),
    cookie_name,
    cookie_value,
    createCookieJar,
    defaultManagerSettings,
    destroyCookieJar,
    httpLbs,
    method,
    newManager,
    parseRequest,
    requestBody,
    requestHeaders,
    responseBody,
    responseHeaders,
    responseStatus,
  )
import Network.HTTP.Types.Status (forbidden403, ok200, badRequest400, unauthorized401)
import Network.Web.Auth
import Network.Web.TestHelper
import Servant
import Servant.Auth.Server
import Servant.Client hiding (responseBody, responseHeaders)
import System.Directory (removePathForcibly)
import Test.Hspec
import System.IO (hClose)
import System.Posix.Temp (mkstemp)

spec :: Spec
spec = parallel $
  around startStopServer $
    describe "Authentication Server" $ do
      let claims = AuthToken 1 1
          registration = RegToken 1 "12345678901234567890123456789012" -- token id is 16-bytes hex-encoded
      it "authenticates user with a valid user/password on BasicAuth" $ \(getServerPort -> authServerPort, _, mgr) -> do
        env <- newClientEnv mgr authServerPort

        res <- fmap getResponse <$> validate (BasicAuthData "user" "pass") [] `runClientM` env

        res `shouldBe` Right NoContent

      it "can register user/password given a valid registration token" $ \(getServerPort -> authServerPort, _, mgr) -> do
        validRegistrationToken <- registrationTokenFor registration sampleKey
        let userRegistration = UserRegistration "user1" "pass1" (SerializedToken $ LBS.toStrict validRegistrationToken)
        initialRequest <- parseRequest ("http://localhost:" <> show authServerPort <> "/signup")
        let request =
              initialRequest
                { method = "POST",
                  requestHeaders =
                    [("content-type", "application/json")],
                  requestBody = RequestBodyLBS $ encode userRegistration
                }
        response <- httpLbs request mgr

        responseStatus response `shouldBe` ok200

      it "cannot register user/password given an invalid registration token" $ \(getServerPort -> authServerPort, _, mgr) -> do
        invalidRegistrationToken <- registrationTokenFor registration wrongKey
        let userRegistration = UserRegistration "user1" "pass1" (SerializedToken $ LBS.toStrict invalidRegistrationToken)
        initialRequest <- parseRequest ("http://localhost:" <> show authServerPort <> "/signup")
        let request =
              initialRequest
                { method = "POST",
                  requestHeaders =
                    [("content-type", "application/json")],
                  requestBody = RequestBodyLBS $ encode userRegistration
                }
        response <- httpLbs request mgr

        responseStatus response `shouldBe` forbidden403

      it "cannot register twice same user" $ \(getServerPort -> authServerPort, _, mgr) -> do
        validRegistrationToken <- registrationTokenFor registration sampleKey
        let userRegistration = UserRegistration "user1" "pass1" (SerializedToken $ LBS.toStrict validRegistrationToken)
        initialRequest <- parseRequest ("http://localhost:" <> show authServerPort <> "/signup")
        let request =
              initialRequest
                { method = "POST",
                  requestHeaders =
                    [("content-type", "application/json")],
                  requestBody = RequestBodyLBS $ encode userRegistration
                }
        _ <- httpLbs request mgr

        response <- httpLbs request mgr

        responseStatus response `shouldBe` badRequest400

      it "can login with password once registered" $ \(getServerPort -> authServerPort, _, mgr) -> do
        validRegistrationToken <- registrationTokenFor registration sampleKey
        let userRegistration = UserRegistration "user1" "pass1" (SerializedToken $ LBS.toStrict validRegistrationToken)
        env <- newClientEnv mgr authServerPort

        resp <- (register userRegistration >> login (Credentials "user1" "pass1")) `runClientM` env

        getResponse <$> resp `shouldBe` Right NoContent

      it "can login registered user and returns Cookie" $ \(getServerPort -> authServerPort, _, mgr) -> do
        cookieJar <- newTVarIO $ createCookieJar []
        env <- pure (ClientEnv mgr) <*> pure (BaseUrl Http "localhost" authServerPort "") <*> pure (Just cookieJar)

        resp <- login (Credentials "user" "pass") `runClientM` env

        cookies <- destroyCookieJar <$> readTVarIO cookieJar

        getResponse <$> resp `shouldBe` Right NoContent
        length cookies `shouldBe` 2

      it "can retrieve a token given valid credentials" $ \(getServerPort -> authServerPort, _, mgr) -> do
        jwt <- authTokenFor claims sampleKey

        initialRequest <- parseRequest ("http://localhost:" <> show authServerPort <> "/tokens")
        let request =
              initialRequest
                { method = "GET",
                  requestHeaders =
                    [("Authorization", LBS.toStrict $ "Bearer " <> jwt)]
                }

        response <- httpLbs request mgr

        responseStatus response `shouldBe` ok200
        responseBody response `shouldBeValidRegistrationTokenFor` sampleKey

      it "cannot retrieve a token given invalid credentials" $ \(getServerPort -> authServerPort, _, mgr) -> do
        jwt <- authTokenFor claims wrongKey

        initialRequest <- parseRequest ("http://localhost:" <> show authServerPort <> "/tokens")
        let request =
              initialRequest
                { requestHeaders =
                    [("Authorization", LBS.toStrict $ "Bearer " <> jwt)]
                }

        response <- httpLbs request mgr

        responseStatus response `shouldBe` forbidden403

      it "authenticates original OPTIONS query even with an invalid user/password" $ \(getServerPort -> authServerPort, _, mgr) -> do
        initialRequest <- parseRequest ("http://localhost:" <> show authServerPort <> "/auth")
        let request =
              initialRequest
                { method = "GET",
                  requestHeaders =
                    [("X-Original-Method", "OPTIONS")]
                }

        response <- httpLbs request mgr

        responseStatus response `shouldBe` ok200

      it "authenticates arbitrary path when user with a valid user/password uses BasicAuth" $ \(getServerPort -> authServerPort, _, mgr) -> do
        env <- newClientEnv mgr authServerPort

        res <- fmap getResponse <$> validate (BasicAuthData "user" "pass") ["foo", "bar"] `runClientM` env

        res `shouldBe` Right NoContent

      it "returns www-authenticate header when auth fails" $ \(getServerPort -> authServerPort, _, mgr) -> do
        initialRequest <- parseRequest ("http://localhost:" <> show authServerPort <> "/auth")
        let request = initialRequest {method = "GET"}

        response <- httpLbs request mgr

        responseStatus response `shouldBe` unauthorized401
        lookup "www-authenticate" (responseHeaders response) `shouldBe` Just "Basic realm=\"test\""

      it "authenticates user with a valid Authentication header" $ \(getServerPort -> authServerPort, _, mgr) -> do
        jwt <- authTokenFor claims sampleKey
        initialRequest <- parseRequest ("http://localhost:" <> show authServerPort <> "/auth")
        let request =
              initialRequest
                { method = "GET",
                  requestHeaders =
                    [("Authorization", LBS.toStrict $ "Bearer " <> jwt)]
                }

        response <- httpLbs request mgr

        responseStatus response `shouldBe` ok200

      it "authenticates request from logged in user" $ \(getServerPort -> authServerPort, _, mgr) -> do
        cookieJar <- newTVarIO $ createCookieJar []
        env <- pure (ClientEnv mgr) <*> pure (BaseUrl Http "localhost" authServerPort "") <*> pure (Just cookieJar)

        _ <- login (Credentials "user" "pass") `runClientM` env

        cookies <- destroyCookieJar <$> readTVarIO cookieJar
        let [token] = LBS.fromStrict . cookie_value <$> filter ((== "JWT-Cookie") . cookie_name) cookies
        initialRequest <- parseRequest ("http://localhost:" <> show authServerPort <> "/auth")
        let request =
              initialRequest
                { method = "GET",
                  requestHeaders =
                    [("Authorization", LBS.toStrict $ "Bearer " <> token)]
                }

        response <- httpLbs request mgr

        responseStatus response `shouldBe` ok200

      it "provides OpenAPI descriptor without authentication" $ \(getServerPort -> authServerPort, _, mgr) -> do
        request <- parseRequest ("http://localhost:" <> show authServerPort <> "/swagger.json")

        response <- httpLbs request mgr

        responseStatus response `shouldBe` ok200

      it "provides public key in JWK format without authentication" $  \(getServerPort -> authServerPort, _, mgr) -> do
        request <- parseRequest ("http://localhost:" <> show authServerPort <> "/keys")

        response <- httpLbs request mgr

        responseStatus response `shouldBe` ok200
        decode (responseBody response) `shouldBe` Just [sampleKey ^. asPublicKey]

authTokenFor :: AuthenticationToken -> JWK -> IO LBS.ByteString
authTokenFor claims key = either (error . show) id <$> makeJWT claims (defaultJWTSettings key) Nothing

registrationTokenFor :: RegistrationToken -> JWK -> IO LBS.ByteString
registrationTokenFor claims key = either (error . show) id <$> makeJWT claims (defaultJWTSettings key) Nothing

shouldBeValidRegistrationTokenFor :: LBS.ByteString -> JWK -> IO ()
shouldBeValidRegistrationTokenFor tok key = do
  verifiedJWT <- verifyJWT (defaultJWTSettings key) (LBS.toStrict tok)
  case verifiedJWT of
    Nothing -> fail "expected a valid registration token"
    Just RegToken {} -> pure ()

newClientEnv :: Applicative f => Manager -> Int -> f ClientEnv
newClientEnv mgr authServerPort = pure $ ClientEnv mgr (BaseUrl Http "localhost" authServerPort "") Nothing

createTestDB :: Text -> Maybe FilePath -> IO FilePath
createTestDB pwds Nothing = do
  (fp, h) <- mkstemp "test-passwords"
  hClose h
  tryMakeDB (10 :: Int) pwds fp
createTestDB pwds (Just fp) =
  tryMakeDB (10 :: Int) pwds fp

tryMakeDB :: (Eq t, Num t) => t -> Text -> FilePath -> IO FilePath
tryMakeDB 0 _ _ = error "failed to create .passwords.test file after 10 attempts"
tryMakeDB n pwds fp =
  (makeDB fp pwds >> pure fp) `catch` (\(_ :: IOException) -> threadDelay 100000 >> tryMakeDB (n - 1) pwds fp)

startStopServer :: ((AuthServer, FilePath, Manager) -> IO ()) -> IO ()
startStopServer = bracket prepareServer (\(s, dbName,  _) -> removePathForcibly dbName  >> stopServer s)
  where
    prepareServer = do
      mgr <- newManager defaultManagerSettings
      dbName <- createTestDB "user:pass" Nothing
      server <- startServer (defaultConfig sampleKey) {authServerPort = 0, passwordsFile = dbName }
      pure (server, dbName, mgr)
