module CVENix.Examples where

import Data.Aeson
import CVENix.CVE
import CVENix.SBOM
import System.Directory
import Data.Time.Clock

exampleParseCVE :: IO ()
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
    putStrLn $ (show $ length $ concat l)
  where
      getCVEIDs p = case p of
                      Nothing -> []
                      Just cve -> do
                          let unwrappedContainer = _cvemetadata_cveId $ _cve_cveMetadata cve
                          [unwrappedContainer]

exampleParseSBOM :: String -> IO ()
exampleParseSBOM fp = do
    file <- decodeFileStrict fp :: IO (Maybe SBOM)
    case file of
      Nothing -> putStrLn "[SBOM] Failed to parse"
      Just f -> do
          putStrLn "Known Deps:"
          case _sbom_metadata f of
            Nothing -> putStrLn "No known deps?"
            Just s -> print s

  where
      getDeps a = case a of
                  Nothing -> Nothing
                  Just d -> Just $ map (_sbomdependency_ref) d
