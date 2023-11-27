{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
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
                run <- mapM (pretty) $ filter isVersionAffected $ matchNames a' cves
                print run

  where
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
                let second = 1000000
                threadDelay $ second * 8
                result <- cveSearch advisoryId
                if _nvdresponse_resultsPerPage result == _nvdresponse_totalResults result then
                    pure $ "We're good"
                else pure $ "More Results than per-page"
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
