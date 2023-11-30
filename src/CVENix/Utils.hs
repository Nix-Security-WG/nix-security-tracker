{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module CVENix.Utils where

import Data.Aeson
import Network.Http.Client
import System.IO.Streams (InputStream)
import Data.ByteString (ByteString)

import OpenSSL
import qualified Data.Text as T
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
