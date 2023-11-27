{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE DeriveGeneric #-}
module CVENix.NVD where

import CVENix.Utils

import qualified Data.Text as T
import Data.Text(Text)
import Data.ByteString
import qualified Data.Text.Encoding as TE
import Data.Aeson
import Data.Aeson.TH
import GHC.Generics (Generic)


import Network.Http.Client
import OpenSSL
import System.IO.Streams (InputStream)
import Data.ByteString (ByteString)


data NVDResponse = NVDResponse
  { _nvdresponse_resultsPerPage :: Int
  , _nvdresponse_startIndex :: Int
  , _nvdresponse_totalResults :: Int
  , _nvdresponse_format :: Text
  , _nvdresponse_version :: Text
  , _nvdresponse_timestamp :: Text
  , _nvdresponse_vulnerabilities :: [Object]
  } deriving (Show, Eq, Ord, Generic)

get' :: URL -> (Response -> InputStream ByteString -> IO a) -> IO a
get' a b = withOpenSSL $ get a b

mconcat <$> sequence (deriveJSON stripType' <$>
    [ ''NVDResponse ])

keywordSearch :: Text -> IO NVDResponse
keywordSearch t = get' ("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" <> TE.encodeUtf8 t) jsonHandler

cveSearch :: Text -> IO NVDResponse
cveSearch t = get' ("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" <> TE.encodeUtf8 t) jsonHandler
