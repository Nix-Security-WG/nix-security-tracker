module CVENix.Matching where

import CVENix.SBOM
import Data.Maybe
import Data.Text (Text)
import qualified Data.Text as T

match :: SBOM -> [Text] -> IO ()
match sbom cves = do
    putStrLn "Known Deps:"
    case _sbom_dependencies sbom of
      Nothing -> putStrLn "No known deps?"
      Just s -> do
          let d = getDeps $ Just s
          case d of
            Nothing -> pure ()
            Just a' -> print $ catMaybes $ matchNames a' cves

  where
      getDeps a = case a of
                  Nothing -> Nothing
                  Just d -> Just $ do
                      let deps = map (_sbomdependency_ref) d
                          stripDeps = T.takeWhile (\x -> x /= '-') . T.drop 1 . T.dropWhile (\x -> x /= '-')
                      map (\x -> (stripDeps x, x)) deps
      matchNames :: Eq a => [(a, b)] -> [a] -> [Maybe (a, b)]
      matchNames a b = flip map a $ \(x, y) -> case x `elem` b of
                                            False -> Nothing
                                            True -> Just (x, y)

