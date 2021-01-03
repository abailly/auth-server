{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Network.Web.DB where

import Control.Exception (throwIO)
import Crypto.KDF.BCrypt
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Data.IORef
import qualified Data.Map as M
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Encoding
  ( decodeUtf8,
    encodeUtf8,
  )
import qualified Data.Text.IO as Text
import Network.Web.Types
--import Preface.Log
import Servant as S
import Servant.Auth.Server as SAS
import System.Random
import Control.Monad.Reader

data AuthDB = AuthDB
  { dbFile :: FilePath,
    dbCache :: IORef (M.Map Login UserData)
  }

data UserData = UserData
  { userSalt :: ByteString,
    userPassword :: ByteString,
    userAuth :: AuthenticationToken
  }

newtype FileDB a = FileDB { runFileDB :: ReaderT AuthDB IO a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadReader AuthDB)

runDB :: MonadIO m => AuthDB -> FileDB a -> m a
runDB authDB a = liftIO $ runFileDB a  `runReaderT` authDB

class DB db where
  authCheck :: BasicAuthData -> db (AuthResult AuthenticationToken)
  registerUser :: Text -> Text -> db (Either DBError AuthenticationToken)

instance DB FileDB where
  authCheck = authCheck'
  registerUser = registerUser'

-- ** User/Password Authentication

authCheck' ::
  BasicAuthData ->
  FileDB (AuthResult AuthenticationToken)
authCheck' (BasicAuthData ident password) = do
  (AuthDB _ authDB) <- ask
  liftIO $ readIORef authDB
    >>= pure . maybe SAS.NoSuchUser checkPassword . M.lookup ident
  where
    checkPassword UserData {..} =
      let encryptedPassword = encrypt userSalt password
       in if encryptedPassword == userPassword
            then SAS.Authenticated userAuth
            else SAS.BadPassword

encrypt :: ByteString -> ByteString -> ByteString
encrypt = bcrypt cost

cost :: Int
cost = 10

-- | Utility function to create a new passwords file from
-- pairs of cleartext `login:pwd` one per line
makeDB :: FilePath -> Text -> IO ()
makeDB file pwds = do
  let encodeLogin lns (l : p : _) = do
        ln <- makeDBEntry l p
        pure (ln : lns)
      encodeLogin _ other = throwIO $ userError $ "invalid password entry " <> show other
  l <-
    foldM encodeLogin [] $
      Text.splitOn ":"
        <$> Text.lines pwds
  Text.writeFile file (Text.unlines l)

makeDBEntry :: Text -> Text -> IO Text
makeDBEntry l p = do
  g <- newStdGen
  let s = BS.pack $ take 16 $ randoms g
  pure $ l <> ":" <> decodeUtf8 (B64.encode s) <> ":" <> decodeUtf8 (B64.encode (encrypt s (encodeUtf8 p)))

data DBError
  = GenericDBError {reason :: Text}
  | DuplicateUserEntry Text
  deriving (Eq, Show)

registerUser' :: Text -> Text -> FileDB (Either DBError AuthenticationToken)
registerUser' login pwd = do
  (AuthDB pwdFile db) <- ask
  usrs <- liftIO $ readIORef db
  case M.lookup (encodeUtf8 login) usrs of
    Just _ -> undefined
    Nothing -> liftIO $ do
      e <- makeDBEntry login pwd
      Text.appendFile pwdFile (e <> "\n")
      readPasswordsFile pwdFile >>= atomicWriteIORef db
      fmap userAuth . maybe (Left $ GenericDBError "failed to register user") Right . M.lookup (encodeUtf8 login) <$> readIORef db

readDB :: FilePath -> IO AuthDB
readDB pwdFile = AuthDB pwdFile <$> (readPasswordsFile pwdFile >>= newIORef)

readPasswordsFile :: FilePath -> IO (M.Map Login UserData)
readPasswordsFile pwdFile =
  M.fromList
    . fmap (\((l, s, p), u) -> (l, UserData s p u))
    . flip zip (fmap (flip AuthToken 1) [1 ..])
    . fmap (\(l : s : p : _) -> (encodeUtf8 l, either (const "") id $ B64.decode $ encodeUtf8 s, either (const "") id $ B64.decode $ encodeUtf8 p))
    . fmap (Text.splitOn ":")
    . Text.lines
    <$> Text.readFile pwdFile
