{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Options.Generic

import CVENix.SBOM
import CVENix.Examples
import CVENix.Matching

data Parameters = Parameters
  { debug :: Bool
  , drv :: NoLabel String
  } deriving (Generic, Show)
instance ParseRecord Parameters

-- https://github.com/Gabriella439/optparse-generic/issues/65
newtype NoLabel a = NoLabel a
  deriving (Generic, Show)

instance ParseFields a => ParseRecord (NoLabel a)
instance ParseFields a => ParseFields (NoLabel a) where
  parseFields msg _ _ def = fmap NoLabel (parseFields msg Nothing Nothing def)


main :: IO ()
main = do
    params <- getRecord "CVENix"
    let NoLabel derivationToAnalyze = drv params
    sbom <- parseSBOM $ derivationToAnalyze
    cves <- exampleParseCVE
    case sbom of
      Nothing ->
        putStrLn "[SBOM] Failed to parse"
      Just s ->
        match s cves $ debug params
