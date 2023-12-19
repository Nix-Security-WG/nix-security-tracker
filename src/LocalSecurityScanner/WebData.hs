-- SPDX-FileCopyrightText: 2023 Arnout Engelen <arnout@bzzt.net>
-- SPDX-FileCopyrightText: 2023 Dylan Green <dylan.green@obsidian.systems>
--
-- SPDX-License-Identifier: MIT

{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
module LocalSecurityScanner.WebData where

import LocalSecurityScanner.Utils
import LocalSecurityScanner.Types

import Data.Aeson.TH
import Data.Text (Text)
import Control.Monad.Trans.Reader
import Data.Map (Map, toList)
import Control.Exception
import Control.Monad.Log
import Control.Monad.IO.Class
import GHC.Generics
import Control.Concurrent
import Prettyprinter
import Control.Monad
import qualified Data.Text.Encoding as TE
import qualified Data.Text as T

import Network.Http.Client

data WebAppResponse = WebAppResponse
  { _webappresponse_code :: Text
  , _webappresponse_cve :: [Text]
  , _webappresponse_status :: Text
  } deriving (Show, Eq, Ord, Generic)

mconcat <$> sequence (deriveJSON stripType' <$> [ ''WebAppResponse ])

webAppApi :: LogT m ann => Map Text Text -> ReaderT Parameters m [WebAppResponse]
webAppApi queryString = do
    go 0
  where
      go :: LogT m ann => Int -> ReaderT Parameters m [WebAppResponse]
      go count = do
          baseURL' <- securityTrackerUrl <$> ask
          case baseURL' of
            Nothing -> pure []
            Just baseURL -> do
              let url = (TE.encodeUtf8 $ T.pack baseURL) <> "/api/v1/issues?" <> (convertToApi $ toList queryString)
              debug' <- debug <$> ask
              v <- liftIO $ (try (getWithHeaders' mempty url jsonHandler)) :: LogT m ann => m (Either SomeException [WebAppResponse])
              when debug' $ logDebug $ pretty $ show url
              case v of
                Left e -> do
                    when debug' $ logDebug $ pretty $ show e
                    logWarning "Failed to parse, waiting for 10 seconds and retrying.."
                    logWarning $ pretty $ "Retry count: " <> show count
                    liftIO $ threadDelay $ 1000000 * 10
                    go (count + 1)
                Right c -> pure c


