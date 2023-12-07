module Main where

import Debug.Trace
import Test.Hspec

import Data.Aeson

import CVENix.NVD
import CVENix.Types
import CVENix.Utils

parseSpec :: Spec
parseSpec = do
  it "needs to parse a CVE" $ do
    let params = Parameters False "test.sbom" (Just "/nix/store/test") False
    Just nvdcve <- decodeFileStrict "tests/resources/CVE-2023-32611.json"
    withApp params $ do
      local <- convertToLocal [nvdcve]
      pure $ length local > 0

main :: IO ()
main = hspec parseSpec
