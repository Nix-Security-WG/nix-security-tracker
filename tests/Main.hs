module Main where

import Debug.Trace
import Test.Hspec

import Data.Aeson

import CVENix.NVD
import CVENix.Types
import CVENix.Utils

parseNVDSpec :: SpecWith (Arg (IO ()))
parseNVDSpec = do
  it "needs to parse a CVE" $ do
    let params = Parameters False "test.sbom" (Just "/nix/store/test") False
    Just nvdcve <- decodeFileStrict "tests/resources/CVE-2023-32611.json"
    decode <- withApp params $ do
      convertToLocal [nvdcve]
    (length $ concat decode) `shouldNotBe` (0 :: Int)

main :: IO ()
main = hspec $ do
    describe "Parse NVD Spec" $ do
        parseNVDSpec
