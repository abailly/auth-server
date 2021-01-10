module Network.Web.ConfigSpec where

import Control.Exception (evaluate)
import Control.Exception.Safe
import Data.Aeson
import qualified Data.ByteString.Lazy as LBS
import Data.Text (isInfixOf, unpack)
import Data.Text.Encoding (decodeUtf8)
import Network.Web.Config
import Network.Web.TestHelper
import System.Directory
import System.IO
import System.Posix.Env
import System.Posix.Temp
import Test.Hspec

spec :: Spec
spec =
  around withTempFile $
    describe "Server Configuration" $ do
      it "raises errors given neithg AUTH_SERVER_ADMIN_PASSWORD nor AUTH_SERVER_PASSWORDS are set" $
        \keyFile ->
          withEnv [] $
            makeConfig keyFile `shouldThrow` anyErrorCall

      it "add 'admin' user to .passwords file given AUTH_SERVER_ADMIN_PASSWORD is set" $
        \keyFile -> withEnv [("AUTH_SERVER_ADMIN_PASSWORD", Just "foo")] $ do
          config <- makeConfig keyFile
          passwords <- decodeUtf8 . LBS.toStrict <$> LBS.readFile ".passwords"

          passwordsFile config `shouldBe` ".passwords"
          passwords `shouldSatisfy` ("admin" `isInfixOf`)

      it "uses default port given AUTH_SERVER_PORT is not set" $
        \keyFile -> withEnv [("AUTH_SERVER_PORT", Nothing), ("AUTH_SERVER_ADMIN_PASSWORD", Just "foo")] $ do
          config <- makeConfig keyFile

          authServerPort config `shouldBe` defaultPort

      it "sets port given AUTH_SERVER_PORT is set to an integer value" $
        \keyFile -> withEnv [("AUTH_SERVER_PORT", Just "12345"), ("AUTH_SERVER_ADMIN_PASSWORD", Just "foo")] $ do
          config <- makeConfig keyFile

          authServerPort config `shouldBe` 12345

      it "throws error given AUTH_SERVER_PORT is not an int" $
        \keyFile -> withEnv [("AUTH_SERVER_PORT", Just "foo"), ("AUTH_SERVER_ADMIN_PASSWORD", Just "foo")] $ do
          config <- makeConfig keyFile
          evaluate config `shouldThrow` anyErrorCall

      it "uses default name given AUTH_SERVER_NAME is not set" $
        \keyFile -> withEnv [("AUTH_SERVER_NAME", Nothing), ("AUTH_SERVER_ADMIN_PASSWORD", Just "foo")] $ do
          config <- makeConfig keyFile

          authServerName config `shouldBe` "localhost"

      it "generates JWK into file given environment variable AUTH_SERVER_JWK is not set" $
        \keyFile -> withEnv [("AUTH_SERVER_JWK", Nothing), ("AUTH_SERVER_ADMIN_PASSWORD", Just "foo")] $ do
          config <- makeConfig keyFile
          Just keyInfile <- decode <$> LBS.readFile keyFile

          publicAuthKey config `shouldBe` keyInfile

      it "uses AUTH_SERVER_JWK content as key given it is set" $
        \keyFile -> withEnv [("AUTH_SERVER_JWK", Just (unpack $ decodeUtf8 $ LBS.toStrict $ encode sampleKey)), ("AUTH_SERVER_ADMIN_PASSWORD", Just "foo")] $ do
          config <- makeConfig keyFile

          publicAuthKey config `shouldBe` sampleKey


withEnv :: [(String, Maybe String)] -> IO a -> IO a
withEnv envs = bracket setup tearDown . const
  where
    setup :: IO ([(String, String)], (FilePath, FilePath))
    setup = (,) <$> setupEnv <*> setupTempDir

    tearDown:: ([(String, String)], (FilePath, FilePath)) -> IO ()
    tearDown (e,d) = tearDownEnv e >> tearDownTempDir d

    setupTempDir :: IO (FilePath, FilePath)
    setupTempDir = do
      cd <- getCurrentDirectory
      (fp, h) <- mkstemp "tmp-auth"
      hClose h
      removePathForcibly fp
      createDirectory fp
      setCurrentDirectory fp
      pure (fp, cd)

    setupEnv :: IO [(String, String)]
    setupEnv = do
      oldEnv <- getEnvironment
      mapM_ addToEnv envs
      pure oldEnv

    tearDownEnv :: [(String, String)] -> IO ()
    tearDownEnv = setEnvironment

    tearDownTempDir :: (FilePath, FilePath) -> IO ()
    tearDownTempDir (fp, cd) = setCurrentDirectory cd >> removePathForcibly fp

    addToEnv (var, Nothing) = unsetEnv var
    addToEnv (var, Just val) = setEnv var val True

withTempFile :: (FilePath -> IO a) -> IO a
withTempFile =
  bracket (mkstemp "test-file" >>= \(fp, h) -> hClose h >> pure fp) (\fp -> removePathForcibly fp)
