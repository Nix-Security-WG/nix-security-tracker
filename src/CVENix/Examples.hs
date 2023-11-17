{-# LANGUAGE ScopedTypeVariables #-}
module CVENix.Examples where

import Data.Aeson
import CVENix.CVE
import System.Directory
import Data.Time.Clock
import Data.Maybe
import Data.Text (Text)

exampleParseCVE :: IO [Text]
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
      pure $ getCVEIDs file
    putStrLn $ "[CVE] Done parsing"
    curTime' <- getCurrentTime
    putStrLn $ "[CVE] Time to run: " <> (show $ diffUTCTime curTime curTime' * (-1))
    pure $ catMaybes $ concat $ l
  where
      getCVEIDs p = case p of
                      Nothing -> []
                      Just cve -> do
                          let unwrappedContainer = _cna_affected $ _container_cna $ _cve_containers cve
                          case unwrappedContainer of
                            Nothing -> []
                            Just a -> map (_product_packageName) a

