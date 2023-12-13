{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module LocalSecurityScanner.Utils where

import LocalSecurityScanner.Types
import Data.Aeson
import Network.Http.Client
import System.IO.Streams (InputStream)
import Data.ByteString (ByteString)
import System.Which

import OpenSSL
import qualified Data.Text as T
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Control.Exception
import Data.Word
import qualified Data.ByteString.Char8 as S
import OpenSSL.Session hiding (read)
import System.IO.Unsafe
import Network.URI
import Network.Http.Inconvenience
import Data.IORef
import Data.Map (Map, toList)
import Data.Time.Clock
import Control.Monad.Trans.Reader
import Control.Monad.Log
import Control.Monad.Log.Colors
import Prettyprinter
import Control.Monad.IO.Class
import Control.Monad

-- Gross workaround to show function names
data Named f = Named
  { _fname :: Text
  , _f :: f
  }

tshow :: Show a => a -> Text
tshow = T.pack . show

sbomnixExe :: FilePath
sbomnixExe = $(staticWhich "sbomnix")

convertToApi :: [(Text, Text)] -> ByteString
convertToApi = TE.encodeUtf8 . T.intercalate "&" . map (\(x, y) -> x <> "=" <> y)

stripType :: Options
stripType = defaultOptions { fieldLabelModifier = stripTypeNamePrefix }
  where
    stripTypeNamePrefix :: String -> String
    stripTypeNamePrefix = drop 1 . namingWrong . dropWhile (\x -> x /= '_') . drop 1 . namingWrong

    namingWrong :: String -> String
    namingWrong a = if head a /= '_' then error ("Naming is wrong for " <> a) else a

stripType' :: Options
stripType' = defaultOptions { fieldLabelModifier = stripTypeNamePrefix }
  where
    stripTypeNamePrefix :: String -> String
    stripTypeNamePrefix = replaceUnderScores . drop 1 . namingWrong . dropWhile (\x -> x /= '_') . drop 1 . namingWrong

    namingWrong :: String -> String
    namingWrong a = if head a /= '_' then error ("Naming is wrong for " <> a) else a

    replaceUnderScores :: String -> String
    replaceUnderScores a = flip map a $ \x -> if x == '_' then '-' else x

withApp :: r -> ReaderT r (LoggingT (WithSeverity (Doc ann)) IO) a -> IO a
withApp params f = runLoggingT (runReaderT f params) (print . renderWithSeverity id . colorize)

timeLog :: forall a m ann. LogT m ann => Named (ReaderT Parameters m a) -> ReaderT Parameters m a
timeLog f = do
    debug' <- timeInfo <$> ask
    case debug' of
      False -> pure =<< _f f
      True -> do
        time <- liftIO $ getCurrentTime
        o <- _f f
        time' <- liftIO $ getCurrentTime
        when debug' $ logMessage $ WithSeverity Debug $ pretty $ "[" <> (T.unpack $ _fname f) <> "] Time to run: " <> (show $ diffUTCTime time' time)
        pure o

getWithHeaders' :: Map ByteString ByteString -> URL -> (Response -> InputStream ByteString -> IO a) -> IO a
getWithHeaders' headers r' handler = withOpenSSL $ getWithHeaders 0 r' handler headers

-- Everything here is from http-streams source code but modified slightly for our uses,
-- some of these are identical because they aren't exposed

getWithHeaders
    :: Int
    -> ByteString
    -> (Response -> InputStream ByteString -> IO a)
    -> Map ByteString ByteString
    -> IO a
getWithHeaders n r' handler headers = do
    bracket
        (establish u)
        (teardown)
        (process)
    where
        teardown = closeConnection

        u = parseURL r'

        q = buildRequest1 $ do
                http GET (pathFrom u)
                setAccept "*/*"
                setContentType "application/json"
                mapM (\(x, y) -> setHeader x y) $ toList headers

        process c = do
            sendRequest c q emptyBody
            receiveResponse c (wrapRedirect u n handler headers)

wrapRedirect ::
    URI ->
    Int ->
    (Response -> InputStream ByteString -> IO β) ->
    (Map ByteString ByteString) ->
    Response ->
    InputStream ByteString ->
    IO β
wrapRedirect u n handler headers p i = do
    if (s == 301 || s == 302 || s == 303 || s == 307)
        then case lm of
            Just l -> getWithHeaders n' (splitURI u l) handler headers
            Nothing -> handler p i
        else handler p i
  where
    s = getStatusCode p
    lm = getHeader p "Location"
    !n' =
        if n < 5
            then n + 1
            else throw $! TooManyRedirects n

establish :: URI -> IO (Connection)
establish u =
    case scheme' of
        "http:" -> do
            openConnection host port
        "https:" -> do
            ctx <- readIORef global
            openConnectionSSL ctx host ports
        "unix:" -> do
            openConnectionUnix $ uriPath u
        _ -> error ("Unknown URI scheme " ++ scheme')
  where
    scheme' = uriScheme u

    auth = case uriAuthority u of
        Just x -> x
        Nothing -> URIAuth "" "localhost" ""

    host = S.pack (uriRegName auth)
    port = case uriPort auth of
        "" -> 80
        _ -> read $ tail $ uriPort auth :: Word16
    ports = case uriPort auth of
        "" -> 443
        _ -> read $ tail $ uriPort auth :: Word16

pathFrom :: URI -> ByteString
pathFrom u = case url of
    "" -> "/"
    _ -> url
  where
    url =
        TE.encodeUtf8 $! T.pack
            $! concat [uriPath u, uriQuery u, uriFragment u]

global :: IORef SSLContext
global = unsafePerformIO $ do
    ctx <- baselineContextSSL
    newIORef ctx
{-# NOINLINE global #-}
