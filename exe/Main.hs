module Main where

import System.Environment
import CVENix.CVE
import CVENix.SBOM
import CVENix.Examples

main :: IO ()
main = do
    args <- getArgs
    exampleParseSBOM $ head args
    () <$ exampleParseCVE
