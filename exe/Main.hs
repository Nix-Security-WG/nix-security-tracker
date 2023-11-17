module Main where

import System.Environment
import CVENix.SBOM
import CVENix.Examples
import CVENix.Matching

main :: IO ()
main = do
    args <- getArgs
    sbom <- parseSBOM $ head args
    cves <- exampleParseCVE
    case sbom of
      Nothing ->
        putStrLn "[SBOM] Failed to parse"
      Just s ->
        match s cves
