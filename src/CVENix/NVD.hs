{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE BangPatterns #-}
module CVENix.NVD where

import CVENix.Utils

import qualified Data.Text as T
import Data.Text(Text)
import qualified Data.Text.Encoding as TE
import Data.Aeson
import Data.Aeson.TH
import GHC.Generics (Generic)
import Network.Http.Client
import OpenSSL
import System.IO.Streams (InputStream)
import Data.ByteString (ByteString)
import Data.Map (fromList)
import System.Environment.Blank
import Control.Concurrent
import Data.Map(Map, size, fromList, toList)
import Control.Exception

data NVDResponse = NVDResponse
  { _nvdresponse_resultsPerPage :: Int
  , _nvdresponse_startIndex :: Int
  , _nvdresponse_totalResults :: Int
  , _nvdresponse_format :: Text
  , _nvdresponse_version :: Text
  , _nvdresponse_timestamp :: Text
  , _nvdresponse_vulnerabilities :: [NVDWrapper]
  } deriving (Show, Eq, Ord, Generic)


type Metrics = Object

data NVDWrapper = NVDWrapper
  { _nvdwrapper_cve :: NVDCVE } deriving (Show, Eq, Ord)

data NVDCVE = NVDCVE
  { _nvdcve_id :: Text --
  , _nvdcve_sourceIdentifier :: Maybe Text
  , _nvdcve_vulnStatus :: Maybe Text
  , _nvdcve_published :: Text --
  , _nvdcve_lastModified :: Text --
  , _nvdcve_evaluatorComment :: Maybe Text
  , _nvdcve_evaluatorSolution :: Maybe Text
  , _nvdcve_evaluatorImpact :: Maybe Text
  , _nvdcve_cisaExploitAdd :: Maybe Text
  , _nvdcve_cisaActionDue :: Maybe Text
  , _nvdcve_cisaRequiredAction :: Maybe Text
  , _nvdcve_cisaVulnerabilityName :: Maybe Text
  , _nvdcve_descriptions :: [LangString] --
  , _nvdcve_references :: [Reference] --
  , _nvdcve_metrics :: Maybe Metrics
  , _nvdcve_weaknesses :: Maybe [Weakness]
  , _nvdcve_configurations :: Maybe [Configuration]
  , _nvdcve_vendorComments :: Maybe [VendorComment]
  } deriving (Show, Eq, Ord, Generic)

data LangString = LangString
  { _langstring_lang :: Text
  , _langstring_value :: Text
  } deriving (Show, Eq, Ord, Generic)

data Reference = Reference
  { _reference_url :: Text
  , _reference_source :: Maybe Text
  , _reference_tags :: Maybe [Text]
  } deriving (Show, Eq, Ord, Generic)

data VendorComment = VendorComment
  { _vendorcomment_organization :: Text
  , _vendorcomment_comment :: Text
  , _vendorcomment_lastModified :: Text
  } deriving (Show, Eq, Ord, Generic)

data Weakness = Weakness
  { _weakness_source :: Text
  , _weakness_type :: Text
  , _weakness_description :: [LangString]
  } deriving (Show, Eq, Ord, Generic)

data Configuration = Configuration
  { _configuration_operator :: Maybe Text
  , _configuration_negate :: Maybe Bool
  , _configuration_nodes :: [Node]
  } deriving (Show, Eq, Ord)

data Node = Node
  { _node_operator :: Text
  , _node_negate :: Maybe Bool
  , _node_cpeMatch :: [CPEMatch]
  } deriving (Show, Eq, Ord, Generic)

data CPEMatch = CPEMatch
  { _cpematch_vulnerable :: Bool
  , _cpematch_criteria :: Text
  , _cpematch_matchCriteriaId :: Text
  , _cpematch_versionStartExcluding :: Maybe Text
  , _cpematch_versionStartIncluding :: Maybe Text
  , _cpematch_versionEndExcluding :: Maybe Text
  , _cpematch_versionEndIncluding :: Maybe Text
  } deriving (Show, Eq, Ord, Generic)

data LocalCache = LocalCache
  { _localcache_cveId :: Text
  , _localcache_pname :: Text
  , _localcache_version :: Text
  } deriving (Show, Eq, Ord, Generic)

get' :: URL -> (Response -> InputStream ByteString -> IO a) -> IO a
get' a b = withOpenSSL $ do
    putStrLn "[NVD] No API Key, waiting 8 seconds.."
    let second = 1000000
    threadDelay $ second * 8
    get a b

mconcat <$> sequence (deriveJSON stripType' <$>
    [ ''NVDResponse
    , ''NVDCVE
    , ''NVDWrapper
    , ''LangString
    , ''Reference
    , ''VendorComment
    , ''Weakness
    , ''Configuration
    , ''Node
    , ''CPEMatch
    , ''LocalCache
    ])

keywordSearch :: Text -> IO NVDResponse
keywordSearch t = nvdApi $ fromList [("keywordSearch", t)]

cveSearch :: Text -> IO NVDResponse
cveSearch t = nvdApi $ fromList [("cveId", t)]

getEverything :: IO [NVDResponse]
getEverything = do
  response1 <- nvdApi mempty
  let st = _nvdresponse_totalResults response1
      results = _nvdresponse_resultsPerPage response1
      (numOfPages, _) = properFraction $ (fromIntegral st / fromIntegral results)
  print numOfPages
  go [] (numOfPages, results)
  where
    go :: [NVDResponse] -> (Int, Int) -> IO [NVDResponse]
    go acc (pages, results) = do
        let st = pages * results
        resp <- nvdApi (fromList [("startIndex", (T.pack $ show st))])
        print pages
        if pages == 0 then
            pure acc
        else go (acc <> [resp]) (pages - 1, results)

nvdApi :: Map Text Text -> IO NVDResponse
nvdApi r = go 0
  where
      go :: Int -> IO NVDResponse
      go count = do
        let baseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
            url = baseUrl <> (convertToApi $ toList r)

        v <- try (withApiKey (get' url jsonHandler) $ \key ->
            getWithHeaders' (fromList [("apiKey", key)]) url jsonHandler) :: IO (Either SomeException NVDResponse)
        case v of
          Left _ -> do
              putStrLn "Failed to parse, waiting for 10 seconds and retrying.."
              putStrLn $ "Retry count: " <> show count
              threadDelay $ 1000000 * 10
              go (count + 1)
          Right c -> pure c

      convertToApi :: [(Text, Text)] -> ByteString
      convertToApi = TE.encodeUtf8 . T.intercalate "&" . map (\(x, y) -> x <> "=" <> y)

withApiKey
    :: IO a
    -> (ByteString -> IO a)
    -> IO a
withApiKey f1 f = do
    apiKey <- getEnv "NVD_API_KEY"
    case apiKey of
      Nothing -> f1
      Just apiKey' -> f (TE.encodeUtf8 $ T.pack $ apiKey')
