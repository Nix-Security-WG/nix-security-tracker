{-# LANGUAGE OverloadedStrings #-}
module CVENix.Matching where

import CVENix.SBOM
import CVENix.Examples
import CVENix.Types
import CVENix.CVE
import Data.Maybe
import Data.Text (Text)
import qualified Data.Map as Map
import qualified Data.Text as T


match :: SBOM -> [Advisory] -> IO ()
match sbom cves = do
    putStrLn "Matched advisories:"
    case _sbom_dependencies sbom of
      Nothing -> putStrLn "No known deps?"
      Just s -> do
          let d = getDeps $ Just s
          case d of
            Nothing -> pure ()
            Just a' ->
              let
                pretty :: Match -> String
                pretty m =
                  let pname = _match_pname m
                      drv = _match_drv m
                      cveId = _advisory_cveId $ _match_advisory m
                      versions = map (\x -> VersionData (_version_version x) (maybeVuln x)) <$> (_advisory_versions $ _match_advisory m)
                  in show pname ++ "\t" ++ show drv ++ "\t" ++ show cveId <> "\n" <> show versions
              in
                mapM_ putStrLn $ map pretty $ matchNames a' cves

  where
      maybeVuln a = if isJust $ _version_lessThan a then
                        (\x -> "lessThan " <> x) <$> _version_lessThan a
                    else if isJust $ _version_lessThanOrEqual a then
                        (\x -> "lessThanOrEqual " <> x) <$> _version_lessThanOrEqual a
                    else Nothing

      getDeps a = case a of
                  Nothing -> Nothing
                  Just d -> Just $ do
                      let deps = map (_sbomdependency_ref) d
                          stripDeps = T.takeWhile (\x -> x /= '-') . T.drop 1 . T.dropWhile (\x -> x /= '-')
                      map (\x -> (stripDeps x, x)) deps
      matchNames :: [(Text, Text)] -> [Advisory] -> [Match]
      matchNames inventory advisories =
                  let
                    advisoriesByProductName :: Map.Map Text Advisory
                    advisoriesByProductName =
                      Map.fromList $ mapMaybe (\a -> case (_advisory_productName a) of
                                                    Just p -> Just (p, a)
                                                    Nothing -> Nothing) advisories
                  in
                    mapMaybe
                        (\package -> case (Map.lookup (fst package) advisoriesByProductName) of
                          Just advisory -> Just (Match { _match_pname = fst package, _match_drv = snd package, _match_advisory = advisory })
                          Nothing -> Nothing
                        )
                        inventory

