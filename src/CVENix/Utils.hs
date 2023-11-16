{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}

module CVENix.Utils where

import Data.Aeson
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic, Rep)
import Type.Reflection (Typeable, typeRep)

import Data.Char (isLower, isPunctuation, isUpper, toLower)
import Data.List (findIndex, isPrefixOf, nub)
import Data.Aeson.Types (Parser)

parseJsonStripType
    :: forall a .
       (Typeable a, Generic a, GFromJSON Zero (Rep a))
    => Value
    -> Parser a
parseJsonStripType = genericParseJSON (stripType @a)

stripType :: forall a . Typeable a => Options
stripType = defaultOptions { fieldLabelModifier = stripTypeNamePrefix }
  where
    typeName :: String
    typeName = "_" <> (map toLower $ show $ typeRep @a) <> "_"

    stripTypeNamePrefix :: String -> String
    stripTypeNamePrefix fieldName =
        if typeName `isPrefixOf` fieldName
            then drop (length typeName) fieldName
            else fieldName


stripType' :: Options
stripType' = defaultOptions { fieldLabelModifier = stripTypeNamePrefix }
  where
    stripTypeNamePrefix :: String -> String
    stripTypeNamePrefix = replaceUnderScores . drop 1 . dropWhile (\x -> x /= '_') . drop 1 . namingWrong

    namingWrong :: String -> String
    namingWrong a = if head a /= '_' then error ("Naming is wrong for " <> a) else a

    replaceUnderScores :: String -> String
    replaceUnderScores a = flip map a $ \x -> if x == '_' then '-' else x

