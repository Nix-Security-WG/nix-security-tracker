{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
module CVENix.Examples where

import Data.Aeson
import CVENix.CVE
import System.Directory
import Data.Time.Clock
import Data.Maybe
import Data.Text (Text)

data Advisory = Advisory
  { _advisory_cveId :: Text
  , _advisory_productName :: Maybe Text
  } deriving Show

exampleParseCVE :: IO [Advisory]
exampleParseCVE = do
    files' <- listDirectory "CVE/cves/"
    let files = filter (\x -> not (x == "delta.json" || x == "deltaLog.json")) files'
    thing <- flip mapM files $ \version -> do
        let prefix = "CVE/cves/" <> version <> "/"
        dir <- listDirectory prefix
        flip mapM dir $ \group -> do
          let prefix' = prefix <> group <> "/"
          dir' <- listDirectory prefix'
          flip mapM dir' $ \x -> do
            pure $ prefix' <> x
    let thing' = concat $ concat thing
    print $ length thing'
    putStrLn $ "[CVE] Parsing " <> (show $ length thing') <> " files"
    curTime <- getCurrentTime
    l <- flip mapM thing' $ \x -> do
      file <- decodeFileStrict x :: IO (Maybe CVE)
      pure $ asAdvisories file
    l2 <- flip mapM thing' $ \x -> do
      file <- decodeFileStrict x
      pure $ getCPEIDs file
    putStrLn $ "[CVE] Done parsing"
    curTime' <- getCurrentTime
    putStrLn $ "[CVE] Time to run: " <> (show $ diffUTCTime curTime curTime' * (-1))
    print $ filter (\a -> _cpe_vendor a /= "microsoft") $ catMaybes $ map parseCPE (concat $ concat $ l2)
    pure $ concat $ l
  where
      asAdvisories :: Maybe CVE -> [Advisory]
      asAdvisories p = case p of
                      Nothing -> []
                      Just cve -> do
                          let
                            cveId = _cvemetadata_cveId $ _cve_cveMetadata cve
                            unwrappedContainer = _cna_affected $ _container_cna $ _cve_containers cve
                          case unwrappedContainer of
                            Nothing -> []
                            Just a ->
                              let names = mapMaybe (_product_packageName) a
                              in map (\n -> Advisory {_advisory_cveId = cveId, _advisory_productName = Just n}) names
      getCPEIDs p = case p of
                      Nothing -> []
                      Just cve -> do
                          let unwrappedContainer = _cna_affected $ _container_cna $ _cve_containers cve
                          case unwrappedContainer of
                            Nothing -> []
                            Just a -> catMaybes $ map (_product_cpes) a
