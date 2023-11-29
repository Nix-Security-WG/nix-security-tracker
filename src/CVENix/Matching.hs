{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
module CVENix.Matching where

import CVENix.SBOM
import CVENix.Types
import CVENix.CVE
import CVENix.NVD

import Data.Maybe
import qualified Data.Set as Set
import Data.Char (isDigit)
import Data.Text (Text)
import qualified Data.Multimap.Set as SetMultimap
import Data.Multimap.Set (SetMultimap)
import qualified Data.Text as T
import Control.Concurrent
import Data.List
import Control.Monad
import Data.Foldable
import Data.Aeson
import System.Posix.Files

match :: SBOM -> [Advisory] -> IO ()
match sbom cves = do
    putStrLn "Matched advisories:"
    case _sbom_dependencies sbom of
      Nothing -> putStrLn "No known deps?"
      Just s -> do
          let d = getDeps $ Just s
          case d of
            Nothing -> pure ()
            Just a' -> do
                foldM_ (getFromNVD) ([] :: [Text]) a'



    where
      getDeps :: Maybe [SBOMDependency] -> Maybe [(Text, Maybe Text, Text)]
      getDeps a = case a of
                  Nothing -> Nothing
                  Just d -> Just $ do
                      let deps = map (_sbomdependency_ref) d
                          split :: Text -> (Text, Maybe Text, Text)
                          split path =
                            let name = T.reverse . T.drop 4 . T.reverse . T.drop 1 . T.dropWhile (\x -> x /= '-') $ path
                                lastSegment = T.reverse . T.takeWhile (\x -> x /= '-') . T.reverse $ name
                                version =
                                  if T.length lastSegment == 0 then Nothing
                                  else if isDigit (T.head lastSegment) then Just lastSegment
                                  else Nothing
                                pname = case version of
                                  Nothing -> name
                                  Just n -> T.reverse . T.drop (T.length n + 1) . T.reverse $ name
                            in
                              (pname, version, path)
                      filter (\(x, _, _) -> if isJust (T.stripSuffix ".conf" x) then False else True) $ map split deps

      getFromNVD :: [Text] -> (Text, Maybe Text, Text) -> IO [Text]
      getFromNVD acc (pname, version, path) = do
          case elem pname acc of
            True -> pure acc
            False -> do
              f <- fileExist $ "/tmp/NVD-" <> T.unpack pname
              case f of
                True -> do
                    putStrLn "Known Vulnerable before, skipping"
                    pure $ acc <> [pname]
                False -> do
                  putStrLn "Running Keyword Search"
                  nvd <- keywordSearch pname
                  putStrLn $ T.unpack pname

                  let configs = map (\x -> (_nvdcve_id $ _nvdwrapper_cve x, _nvdcve_configurations $ _nvdwrapper_cve x)) $
                                    _nvdresponse_vulnerabilities nvd
                      (versions :: [(Text, [CPEMatch])]) = flip map configs $ uncurry $ \cveId -> \case
                        Nothing -> ("Fail", [])
                        Just conf -> do
                            let cpeMatch = (concat (map _node_cpeMatch (concat (map _configuration_nodes conf))))
                            (cveId, cpeMatch)

                      vulns = flip concatMap versions $ uncurry $ \cveId x' -> flip map x' $ \x -> do
                        let nvdVer = _cpematch_versionEndIncluding x
                            nvdCPE = (\x -> pname == _cpe_product x) <$> (parseCPE $ _cpematch_criteria x)
                        case nvdCPE of
                          (Just False) -> Nothing
                          (Just True) -> case nvdVer of
                            Nothing -> Nothing
                            Just ver -> do
                              let ver' = splitSemVer ver
                                  localver = splitSemVer <$> version
                              case (ver', localver) of
                                (Just v, Just (Just lv)) -> do
                                    if _semver_major v >= _semver_major lv && _semver_minor v >= _semver_minor lv then
                                        Just (cveId, lv, v)
                                    else Nothing
                                (_, _) -> Nothing
                          _ -> Nothing

                  flip mapM_ vulns $ \case
                    Just (cveId, localver, nvdver) -> do
                        putStrLn $ T.unpack cveId
                        putStrLn $ "VULN"
                        putStrLn $ show localver
                        --encodeFile ("/tmp/NVD-" <> T.unpack pname) $ LocalCache cveId pname (T.pack $ prettySemVer localver)
                    Nothing -> pure ()
                  pure $ acc <> [pname]







match' :: SBOM -> [Advisory] -> IO ()
match' sbom cves = do
    putStrLn "Matched advisories:"
    case _sbom_dependencies sbom of
      Nothing -> putStrLn "No known deps?"
      Just s -> do
          let d = getDeps $ Just s
          case d of
            Nothing -> pure ()
            Just a' -> do
                --run <- mapM (pretty) $ filter isVersionAffected $ matchNames a' cves
                --mapM_ putStrLn run
                foldM_ (fetchFromNVD) ([] :: [Text]) $ nub $ filter isVersionAffected $ matchNames a' cves

  where

      fetchFromNVD :: [Text] -> Match -> IO [Text]
      fetchFromNVD acc m = do
          let pname = _match_pname m
          case elem pname acc of
            True -> do
                pure acc
            False -> do
              response <- keywordSearch pname
              putStrLn $ T.unpack pname
              let configs = map (\x -> (_nvdcve_id $ _nvdwrapper_cve x, _nvdcve_configurations $ _nvdwrapper_cve x)) $ _nvdresponse_vulnerabilities response
              let versions = flip map configs $ uncurry $ \cveId -> \case
                    Nothing -> ("Fail", [])
                    Just conf ->
                        (cveId, catMaybes $ map (_cpematch_versionEndIncluding) (concat (map _node_cpeMatch (concat (map _configuration_nodes conf)))))
              print $ _match_version m
              putStrLn "Vulnerable versions: "
              let vulns = flip concatMap versions $ uncurry $ \cveId x' -> flip map x' $ \x -> do
                    let nvdVer = splitSemVer x
                        matchVer = splitSemVer (_match_version m)
                    case (nvdVer, matchVer) of
                      (Nothing, Nothing) -> (matchVer, cveId, False)
                      (Just nvd, Just l) -> do
                        if _semver_major nvd >= _semver_major l && _semver_minor nvd >= _semver_minor l && nvd /= l then
                          (matchVer, cveId, True)
                        else
                          (matchVer, cveId, False)
                      _ -> (matchVer, cveId, False)
              flip mapM_ vulns $ \(x, cveId, y) -> do
                  if y == True then do
                    putStrLn $ "CVEID: " <> T.unpack cveId
                    print $ prettySemVer <$> x
                    putStrLn $ "Vulnerable!"
                  else pure ()
              putStrLn ""
              pure $ acc <> [pname]

      pretty :: Match -> IO String
      pretty m = do
          let pname = _match_pname m
              drv = _match_drv m
              advisoryId = _advisory_id $ fst $ _match_advisory m
              versionSpec = _advisory_product_versions $ snd $ _match_advisory m
              -- TODO deduplicate if needed?
              versions = map (\x -> VersionData (_version_version x) (maybeVuln x) (_version_status x)) <$> versionSpec
          prettyVersions <- case versions of
            Nothing -> do
                putStrLn "Running"
                putStrLn $ show advisoryId
                putStrLn "Waiting 8 seconds...."
                result <- cveSearch advisoryId
                pure $ show $ _nvdresponse_totalResults result
            Just a -> pure $ show a
          pure $ show pname ++ "\t" ++ show drv ++ "\t" ++ show advisoryId <> "\n" <> show prettyVersions <> "\n"

      isVersionAffected :: Match -> Bool
      isVersionAffected match' =
        let
          product' = snd $ _match_advisory match'

          defaultStatus :: Text
          defaultStatus = maybe "unknown" id (_advisory_product_defaultStatus product')

          versions :: [Version]
          versions = maybe [] id (_advisory_product_versions product')

          matches :: Version -> Bool
          matches v =
            if _version_version v == _match_version match' then True
            -- TODO take into account 'lessThan'/'lessThanOrEqual' if present
            else False

          getStatus :: [Version] -> Text
          getStatus [] = defaultStatus
          getStatus (v:vs) =
            if (matches v)
              then _version_status v
              else getStatus vs
        in getStatus versions == "affected"

      maybeVuln a = if isJust $ _version_lessThan a then
                        LessThan <$> _version_lessThan a
                    else if isJust $ _version_lessThanOrEqual a then
                        LessThanOrEqual <$> _version_lessThanOrEqual a
                    else Just Exact

      getDeps a = case a of
                  Nothing -> Nothing
                  Just d -> Just $ do
                      let deps = map (_sbomdependency_ref) d
                          split :: Text -> (Text, Maybe Text, Text)
                          split path =
                            let name = T.reverse . T.drop 4 . T.reverse . T.drop 1 . T.dropWhile (\x -> x /= '-') $ path
                                lastSegment = T.reverse . T.takeWhile (\x -> x /= '-') . T.reverse $ name
                                version =
                                  if T.length lastSegment == 0 then Nothing
                                  else if isDigit (T.head lastSegment) then Just lastSegment
                                  else Nothing
                                pname = case version of
                                  Nothing -> name
                                  Just n -> T.reverse . T.drop (T.length n + 1) . T.reverse $ name
                            in
                              (pname, version, path)
                      map split deps

      matchNames :: [(Text, Maybe Text, Text)] -> [Advisory] -> [Match]
      matchNames inventory advisories =
                  let
                    advisoriesByProductName :: SetMultimap Text (Advisory, AdvisoryProduct)
                    advisoriesByProductName =
                      SetMultimap.fromList $ concat $ map (\a -> mapMaybe
                                                          (\ap -> case (_advisory_product_productName ap) of
                                                                  Just p -> Just (p, (a, ap))
                                                                  Nothing -> Nothing) $ _advisory_products a) advisories
                  in
                    concatMap
                        (\package ->
                            let (pname, version, path) = package
                            in
                              case version of
                                Nothing -> []
                                Just v -> map (\matched_advisory -> Match pname v path matched_advisory) (Set.toList $ SetMultimap.lookup pname advisoriesByProductName)
                        )
                        inventory
