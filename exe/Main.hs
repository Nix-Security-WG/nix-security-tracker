{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Options.Applicative

import CVENix.SBOM
import CVENix.Examples
import CVENix.Matching

data Parameters = Parameters
  { debug :: !Bool
  , sbom :: !String
  } deriving (Show, Eq, Ord)

programOptions = Parameters
  <$> switch (  long "debug"
             <> short 'v'
             <> help "Debug logging"
             )
  <*> strOption (  long "drv"
                <> value "sbom.cdx.json"
                <> help "SBOM to ingest"
                <> metavar "SBOM JSON"
                <> showDefault
                )

parameterInfo = info (helper <*> programOptions) (fullDesc <> progDesc "Nix Security Scanner" <> header "Nix Security Scanner")


main :: IO ()
main = do
    params <- execParser parameterInfo
    sbom <- parseSBOM $ sbom params
    cves <- exampleParseCVE
    case sbom of
      Nothing ->
        putStrLn "[SBOM] Failed to parse"
      Just s ->
        match s cves $ (debug params)
