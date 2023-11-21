{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
module CVENix.Examples where

import Data.Aeson
import CVENix.CVE
import System.Directory
import Data.Time.Clock
import Data.Maybe
import Data.Text (Text)
import CVENix.Types


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
    putStrLn $ "[CVE] Done parsing"
    curTime' <- getCurrentTime
    putStrLn $ "[CVE] Time to run: " <> (show $ diffUTCTime curTime curTime' * (-1))
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
                              let names = map (\x -> (_product_packageName x, _product_versions x)) a
                              in map (\(n, v) -> Advisory cveId n v) names
      getCPEIDs p = case p of
                      Nothing -> []
                      Just cve -> do
                          let unwrappedContainer = _cna_affected $ _container_cna $ _cve_containers cve
                          case unwrappedContainer of
                            Nothing -> []
                            Just a -> catMaybes $ map (_product_cpes) a
      getVersions p = case p of
                        Nothing -> []
                        Just cve -> do
                          let unwrappedContainer = _cna_affected $ _container_cna $ _cve_containers cve
                          case unwrappedContainer of
                            Nothing -> []
                            Just a -> catMaybes $ map (_product_versions) a
