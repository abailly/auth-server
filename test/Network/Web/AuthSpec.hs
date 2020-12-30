{-# LANGUAGE ScopedTypeVariables #-}

module Network.Web.AuthSpec where

import Control.Concurrent (threadDelay)
import Control.Concurrent.STM(newTVarIO, readTVar, atomically)
import Control.Exception (IOException, bracket, catch)
import Crypto.JOSE
import Data.Aeson (decode)
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import Network.HTTP.Client
  ( defaultManagerSettings,
    createCookieJar, destroyCookieJar,
    httpLbs,
    method,
    newManager,
    parseRequest,
    requestHeaders,
    responseHeaders,
    responseStatus,
  )
import Network.HTTP.Types.Status (ok200, unauthorized401)
import Network.Web.Auth
import Servant
import Servant.Auth.Server
import Servant.Client hiding (responseHeaders)
import System.Directory (removePathForcibly)
import Test.Hspec

spec :: Spec
spec = around startStopServer $
  describe "Authentication Server" $ do
    let claims = AUser 1 1

    it "authenticates user with a valid user/password on BasicAuth" $ \AuthServer {authServerConfig = AuthConfig {authServerPort}} -> do
      env <- ClientEnv <$> newManager defaultManagerSettings <*> pure (BaseUrl Http "localhost" authServerPort "") <*> pure Nothing

      res <- fmap getResponse <$> validate (BasicAuthData "user" "pass") [] `runClientM` env

      res `shouldBe` Right NoContent

    it "can login registered user and returns Cookie" $ \AuthServer {authServerConfig = AuthConfig {authServerPort}} -> do
      cookieJar <- newTVarIO $ createCookieJar []
      env <- ClientEnv <$> newManager defaultManagerSettings <*> pure (BaseUrl Http "localhost" authServerPort "") <*> pure (Just cookieJar)

      resp <- login (Credentials "user" "pass")  `runClientM` env

      cookies <- destroyCookieJar <$> atomically (readTVar cookieJar)

      getResponse <$> resp `shouldBe` Right NoContent
      length cookies `shouldBe` 2

    it "authenticates original OPTIONS query even with an invalid user/password" $ \AuthServer {authServerConfig = AuthConfig {authServerPort}} -> do
      mgr <- newManager defaultManagerSettings
      initialRequest <- parseRequest ("http://localhost:" <> show authServerPort <> "/auth")
      let request =
            initialRequest
              { method = "GET",
                requestHeaders =
                  [("X-Original-Method", "OPTIONS")]
              }

      response <- httpLbs request mgr

      responseStatus response `shouldBe` ok200

    it "authenticates arbitrary path when user with a valid user/password uses BasicAuth" $ \AuthServer {authServerConfig = AuthConfig {authServerPort}} -> do
      env <- ClientEnv <$> newManager defaultManagerSettings <*> pure (BaseUrl Http "localhost" authServerPort "") <*> pure Nothing

      res <- fmap getResponse <$> validate (BasicAuthData "user" "pass") ["foo", "bar"] `runClientM` env

      res `shouldBe` Right NoContent

    it "returns www-authenticate header when auth fails" $ \AuthServer {authServerConfig = AuthConfig {authServerPort}} -> do
      mgr <- newManager defaultManagerSettings
      initialRequest <- parseRequest ("http://localhost:" <> show authServerPort <> "/auth")
      let request = initialRequest {method = "GET"}

      response <- httpLbs request mgr

      responseStatus response `shouldBe` unauthorized401
      lookup "www-authenticate" (responseHeaders response) `shouldBe` Just "Basic realm=\"test\""

    it "authenticates user with a valid Authentication header" $ \AuthServer {authServerConfig = AuthConfig {authServerPort}} -> do
      Right jwt <- makeJWT claims (defaultJWTSettings sampleKey) Nothing
      mgr <- newManager defaultManagerSettings
      initialRequest <- parseRequest ("http://localhost:" <> show authServerPort <> "/auth")
      let request =
            initialRequest
              { method = "GET",
                requestHeaders =
                  [("Authorization", LBS.toStrict $ "Bearer " <> jwt)]
              }

      response <- httpLbs request mgr

      responseStatus response `shouldBe` ok200

    it "reloads the content of passwords file when it changes" $ \AuthServer {authServerConfig = AuthConfig {authServerPort}} -> do
      threadDelay 100000
      createTestDB "user:pass1"
      threadDelay 200000

      env <- ClientEnv <$> newManager defaultManagerSettings <*> pure (BaseUrl Http "localhost" authServerPort "") <*> pure Nothing

      res <- fmap getResponse <$> validate (BasicAuthData "user" "pass1") [] `runClientM` env

      res `shouldBe` Right NoContent

createTestDB :: Text -> IO ()
createTestDB pwds = go (10 :: Int)
  where
    go 0 = error "failed to create .passwords.test file after 10 attempts"
    go n = makeDB ".passwords.test" pwds `catch` (\(_ :: IOException) -> threadDelay 100000 >> go (n - 1))

startStopServer :: (AuthServer -> IO ()) -> IO ()
startStopServer act = bracket prepareServer (\s -> removePathForcibly ".passwords.test" >> stopServer s) act
  where
    prepareServer = do
      createTestDB "user:pass"
      startServer (defaultConfig sampleKey) {authServerPort = 0, passwordsFile = Just ".passwords.test", reloadInterval = 100000}

sampleKey :: JWK
Just sampleKey = decode "{\"qi\":\"RhMSXAdvpyYdnh3gd37ZldmNuB6qKKdResPq1hYnZ3VlXX9I9Qfm-Qb1zPjo95jzETimhLaHaDN6TVkkOQb76nz5VWhAZv7XD8Sa4hFmE231Nm89x6ML3bnNKuuw0DAZDIWpGV7dN30S2WIqCFdX3Q0-vIn32V0D9M99f8ieS9s29YNpeo_j7iljPv5y24jJ1ilvAQJiNJlpVwQjG0MC5cVo99vjt4nT_6H6N9MAbkaOXAz7tWfR3HnMQHsSG5PXcgvz48FLyiry0InVtbRZymZ7D2qOdxHAuhqHA4sTn8FKSVJjbERPUVRzPtmYNl9xgAkR6GhvB43J1XYISmPMg03RkFtpqVzTfifDsQXUuf7B_79v8OiLcihGyD0y90B6ar33iYv_KojWa4OeqKjT4fpC7OTMPY7KRvu13S6goSMNmeE_Z92XLsX4ZwRClBrzvr6AaR5YCYbnYflGqFHZm5OiEuPKdUm66O3MFIqBWZ0K60F9Ttfp7Ka9Z-gQFUqHlJdN4O0R6kkqatLWoS0Yr2I-aQW3WBq26fa6wdRMRG1nXSo4AZQVocW5JBNSVfhynmRusCY6tzeQ3JIHkAqXN2F6W2RM2GkIBEBssh9GeIcFXPHqpB0sbf5_giiYL_eCK4a8d6EIDxP8-zK8lwgo_ni0IDGSWR6nk2_dFBzU9SE\",\"p\":\"8JPW3cOxnU7e2E6EO3dV3_qhpG2wXS_Ps_WPifHCNJIjuWWlQrjuhUZxfY_ns2eAUKomC-THQsd98UaRgBv-38s16A8g3O1WVuOwd61FuSCrUfIr56NznXOC5qkK67SXxQjxzibJQxC3pcPa8H5mfwYuVW-LAaU7-RgTlL-G0nadhqYkNyBv3jBsW4UTxVNx0ikhzWegSM9ZaNFYXozRDMEbY_-mmrCF02vA5AWbeULwo2YE9_lvq9v3r_xfM9Wvl9PsvRdnna4ZL8Cok87zPdglZgsEIcsrI4LRTa7ZdqsoC7WvLtO6j6DulVD_kXlx1ZFDQzbm65p-5dLXLXjoFb6b8PXQyHLdi9rQADwW5p439b_nuvOGXWCyE_yBXjSBLNGgdvPL33QSNeUcS4ZmlXPn2FF_TJOr5YuXoqzzqYwQVL41zxUXi6y17yueqvAHvVaHHINkvESg9KeTYZ-hl8oDJWwV3KcguAB5QZ1DWcuRGb9wX_RQyA9PFgk8Ea-hJFBIfk2J8dnjokeREwt-6_OuXLXHihlas52G_f1z3wz0VtEHi4uUd5BDYzDqhG0GTXN4xrFXk5S6qiBVdHFPSZZDkex-J-UU_VS5oQOJpr01qcFkdvrF8Ex7e178KJUxXdWPm_-p3OGBQJot2Q5qPCXVnbPffTNQK3Qzmuz0aBk\",\"n\":\"6D-Xvj_stgEBAKdXIVtBr3YgaDujb_yb4cwx5I9HKBfBvhXtENxFVqJ3EdDRvuGBCk3bF2U87k13ilG9qk87JWn6T8hSXstFTyUe6IWZLEsL1Azjk4i2BqfGA9c-C-qTaEW1GiUtIifhn2F1J3gqaPsSsk3ujJJi2q6AD1alXbrKzB5sHhqgb25LOMARefV2uh2mis8X21Gqk7iy4rcKEOPxcVLCPXLxt7KtwiHXHC9rbEfszYo3vwhgm-0AsqX8tqKLMFAAx08t5rRxVSSjUSQ8TBBS3zYSm8NQ_I2E4JjuTqInt4kab_LhXRjoB_tax6A8kn0CvwkmBZkVfzt4LFhva7KwjvftL9Bsu7Va5YUcm-OtJLSfwcU0p8yLEV-W3v6-nrPAA-4XeNBxYozXlBasHIvII6F0flYLZGvZyC6N10E5LakxWfYxW2ceCQiN7c8XwIr77WewF2Ragdwd65NbF73pFGKBBboTIdV3xxx5huPCcaHukOGrz2RNXkA-i8Gkc4raB34L0qr3LFt1d0YEkqzuP48QrzT3cxklqrbBm_E5KD3JdQYM4mxf28dwLWKyUJaSUYZyQcY5QvMXi3ZaLX-pM8jJbOkofqrHGm06XToxjAe_89KtXiM8expS0ZmZdlYjNERFXEiWsjchFgl_D15LjDnnzrh40_B54NsXJvurzX0xhJUV3rMfBlz1uQT4irc3maT_sIBpzLMmHxK-ldoa8i0BcEepxX7fus_RplHs04ytMt8sQZDbFu6gN4iGBykl9N2kBTHO48rEUb5BG-A2SJKNOs9xBf2xbOy_a1aJpDfNljk51WgolAb50HsAFf_18Fb6VBL_S6qFu3NsQFcL5IwUqxV2B1HEJMQQ6ZSC76-umkh8Pivr8hg-F-eMJCcYRh4FUICB67YJG2YCtCbqaamOw9VrZHKRcP_3LAkREMNW6HoFapZVKB_iimqhwRepsOttQvWEBV-DMnVrk8uIG1KDGZ23rax9awDJL7Aa87FdgSjH337cwNOrRB847Z4UmExniKV6aNsQLLw58b7K7F-jk8l4By2mprNuNalwpEDADQ-sUaEbd9ZLuV4crnoQ0swFTK0jWPL_Y-stJcABY6jhKp6yCoR12ap0CY5zbYbnPAbEd-SKXEBgEmQ9-NXxBH3BenX0DMEajE1nCkeN6s0PrvwlLo6YGIYVYm8gkJPLioMXesDVG42FjLgHVoLRzlAAVs8Dqux_cFdPZr4Bkx7AgBE50EOcM9y005ygBcHf6uHIfWeTjgJzsjY6gez1iSHw6AnmH7dcAAJuu4NdyzWM81SnxE-eBROshOZro1IV7yg4dowDnBPQxi0yoXhXrulCmnOpQPlL_Q\",\"q\":\"9yMQMagyoRa8JFnB17CHG-Z9GgmygOm0sU61fxy1Tzq5mWGSx9nmnUfYmO_mSIVSmy84nKJkrcg0jVr7K48-S4jM14Yqscfv6m_8RtJXtXdkDWHDlMBrKRIo4xKBARqsfzOR6USXdl29CTp8bMDq0h_cSBs8QI5JM__g2wJFyE7IKpmvF951iLupB_MTwKxGroAf86Gkqw2K0Zkn4LbueR1pFv1SZeq9PXtkQs6pSHECZajn0xymIZ4bfyKwiBAoAuIPjspIfRns9zxLL0lkPU46wp_l_pBID96fVO-kW4gwsSoVtM_x2ZHQFNN5Nv2frJHZQcgpZxueyfS39hCVx_fcjimmKdHejiTVhN9JsfNrJRiLxtFg-Y12NDmX-273OiPtE-7PjCokj5a0VGFfcr2GZ6jO26G-2tkMZEqCQwh3eo35YJifeaLmrQfNDMFbR4ZbWqZEmoByTsy1i8sUnYY1is9931IN3amdXG3N74_5WX9onoVtqMT1Hp-fs1DGZX3-s1bq1vfCCIF9pYjANh01avqV1BPmzuIGeDHe5gC6vrsmR75KitDz8nfL-JaEKvAxRAhsVBgz6W4s2jVM4mKyRQnTgGSpz2YHkW60e8Bo5Uaj0kIywTpwLn-2fKYxu0SSWbIpleqsPY2wibQXNL68nSJMYnd4pCQEqwrLz4U\",\"d\":\"5mF-svhSZVCln_JfWfVeOSFikELoo0PflaKqs2D1Yu3-AANcAGegWIoctw1_omurR39nn9OLF5C8zfa7v9-MelagONgr7WCSRio6eMld4jQnbZfDgCwS9JMkt9ah88wjoUHUnjTWipUpGKLiRd7Lowu7xifMRKFJcke7PHvk2g9a8BQVh9892ot8DrVoIKS_u2uCMxuvPJ3MKXED8iVD1PFoJdPEXpRQ9rpF5tcOvSTE2MqYOmOrXNKAkuwMzyocf0bJ74jM3OjMTZgc_Cq13t2k-ocOzeCjoOOkyIHRl8HcUyBDaaqVEQvLRkBYmuJZcMCglWdwe_QlRVRPoMBrOwIWtKyyu39wRwfndGQ34ImkkXbN4CVUfDCVRQZ_xSIfVOE6Uc9Y4A0kN3H9p5aymnHLFR4L0FxuZIwSDPF3PT4A8c__Wi4FiInQ-CxX_PoBYC8YDqVPtnYulWW06jBhdbfcmraGKPR1rCqio-NPR7IVUxtHXNUXA5z4g2ep35627IeQDBVmphwAul9hhRzMbx6DlsP4KhBOqp5OAFynoqpbb8dfvW1dE7qGuWxrwmYZ_styusJCLqDBYkGxt5nQd0VVuuByBa5dMK4wv0XE74_-X1BEqfVeEg2gcEtfyXWZRdWqB1r23PgEHcDby7koFuYgpiwRoO4n5kXThdl77PFEP1gSsDW6pbXNoNGW_oXQXrxAS8BWb-Tnigl0tAAPyqC3amgU-Z7-twqFNpJ7x2_gvOdrjqA_P1YofRzptVh47OFcssLvL-OJwTKPye-2o9S4n09J93Xl3PWbExu7v_DLEO2MH1oq4i_y0dgU-tigkUGeXyBGGz266rIeDNKYKrAAGkiT7vLiUx9NSbrLno_T7hqpwVmKGCkFq2UWjHPxeuusrkLos1EzNferapuyCwpgXehD_vIIwJPumZ2q2rmUzn1odIQOFtsZf4POg911wiUpbDiLjL8QG4dm2Fl06_uVyXr1VsLr2rrUgI9MJtXqkq0sCVhejn9YzRW9kwiIOMV0du0W_fGdGBNfUBX142KOGNc3n_GThpFYD3yl0FiTnqKNzQOlt7dtdBe1GnknpAbp1cfgnY1JfyraflJFgHe_NvyTKnrabmupIo-mwenqfFO2j9OPZI-0INISYv993tK5bU3ptGg6vB52AIJZbpdUoy3vGGU6axgffWCgScKzDqp2NL-mQZ9UHQjjh8zYnpMy-Csagl8PsaGTKVKbMxZRHV_8qiiS_aOC0UEJ-TL6RMpMEu_BeiJxFbFUIn6xEzCuDmRlwkUkM890fNZNl-xekXm8MERqHSYhBc4qdFe2RCjSHlZSmXZBrZ5KesjaV78ToxUd0Gon68ThflciwQ\",\"dp\":\"fMqDOzeGi23dBGD-EIafYfZ1IIDRahUh7VxkX46rSW_A3iuOpOSevT1EI3ihHJuEoNMRtzut7MLkXmJXmRdshxO226_1QQRPs_SZlgqoTxZWJ8Sx548Oqs6_SPzIsGlWDJvOKjxOS96BFJhamkNG0X8YS7L3bRwT1usZRSBwQ_3JSo4l3P6TaLK_kl2eWs4lDXnOkei96Oa9nzRwXWM4ESCeH6n99uG4GWocfWs3MZh6kJeb3jFiLsiEW6JSk-W1FtGUTKW2VsF3SSDrkPhZjmvvQlZWh10G_H2gKmaXYQn5VNGilGy5qkU1XPjOCNzxInIebOAuumnCh15txaWg5Z6g70XjTgbfSutu16BT1L6fkndAMeaefRNqbBmf1YjwtJnsXaeqyjdANvqoSbjmv4GG8tubZ9J16TUWrAiAwCLqWbrs2IU9WHN3UB_VRyAJM7qNjUnO2CXVQ_Mk7Q_L15uvNBsz3-hFfYypWVLFG_APTUbTeMKXoJ7oTCrwINB0iwyl_fYkpvJ6NLRg2XsuFCCsAmU8ozLxrJf67QcqsrnaiKoW-tilY7vOaMZ378dJ7KUIMjDNl70fcp4hFaytDyPF2wzMh885qwrm21GldntROcQaY-lDAZn6t40WycpR-DWOL8JXjz7eN--B9sSWcKrDevFR7XTPkirNlgBx6wk\",\"e\":\"AQAB\",\"dq\":\"dmGsYyz_u5xpWTxJl2ku_xVkfbGBeTD55ike1ZnJ2_70Yt2TcvoU9ugwf-oCtGBw1ndDNfywH3KUgdXAFPiTzZjlDqRtFSYB7ZnhDYe6jel32tUm271kV5MkVMlLVF0Tngb08PlzWDbE04PZkDrFAQxT95JcRUwjEq6SZjZreO0MAyQE9HkScgH6kR1GK_gaD4K-S3T1rR5ajdZAfOsDxq5o5aNI8hsEtUvDFiFqg5HmpQ3Ipp7FkbrrzvWt_C9JC0CAVVTeblaZ5UBTf343bwpnKU1w3YT9j-SDDCuS3mmZcXQIW8l0P1USiLdYDBhngUGIAXPBKWvYn0MDT_JX3ScE1nBq8QNgCVTplrFi2sQQYf-lDQLE4iV6JsAj5kQcVxRYf0DY2HpjcwisrvLJxuu0UzlQhXKwOqLXxb7PMQ8ANIuHllblpV18BAyFk4OXluZsIjsdB6lZmBeFK0aHRIHCahDEadIjZDfYcisDB6s-tTlLwwuFIN_fzuCFnl6l-n3lIMEU0w5xOqPUrROZhxJswSbx2FoEKLuqf67b5-8XhT-esaUcjexTvqTV5ukqvGq8HquuQIYrb7jf8VKw1oySenGfh5Qwp3FnVKnj-JeNZ65z0Mb3CwpULGHu5zyw-9R4ClFGjFKSWRXjJ8NFjnWDYf3I-y3hczbxqYENagU\",\"kty\":\"RSA\"}"
