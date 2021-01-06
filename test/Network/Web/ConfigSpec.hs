module Network.Web.ConfigSpec where

import Control.Exception.Safe
import Data.Aeson
import qualified Data.ByteString.Lazy as LBS
import Network.Web.Config
import Network.Web.TestHelper
import System.Directory
import Data.Text.Encoding(decodeUtf8)
import Data.Text(unpack)
import System.IO
import System.Posix.Env
import System.Posix.Temp
import Test.Hspec

spec :: Spec
spec =
  around withTempFile $
    describe "Server Configuration" $ do
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
withEnv envs = bracket setupEnv tearDownEnv . const
  where
    setupEnv :: IO [(String, String)]
    setupEnv = do
      oldEnv <- getEnvironment
      mapM_ addToEnv envs
      pure oldEnv

    tearDownEnv :: [(String, String)] -> IO ()
    tearDownEnv = setEnvironment

    addToEnv (var, Nothing) = unsetEnv var
    addToEnv (var, Just val) = setEnv var val True

withTempFile :: (FilePath -> IO a) -> IO a
withTempFile =
  bracket (mkstemp "test-file" >>= \(fp, h) -> hClose h >> pure fp) (\fp -> removePathForcibly fp)
