{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}


module CVENix.SBOM where

import GHC.Generics
import Data.Aeson
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic, Rep)
import Type.Reflection (Typeable, typeRep)

import Data.Char (isLower, isPunctuation, isUpper, toLower)
import Data.List (findIndex, isPrefixOf)
import Data.Aeson.Types (Parser)


type Component = Object
type Service = Object
type SBOMReference = Object
type SBOMDependency = Object
type Composition = Object
type Vulnerability = Object
type Annotation = Object
type Formulation = Object
type Property = Object
type Signature = Object

data SBOM = SBOM
  { _sbom_bomFormat :: Text
  , _sbom_specVersion :: Text
  , _sbom_serialNumber :: Maybe Text
  , _sbom_version :: Maybe Text
  , _sbom_metadata :: Maybe Metadata
  , _sbom_components :: Maybe [Component]
  , _sbom_services :: Maybe [Service]
  , _sbom_externalReferences :: Maybe [SBOMReference]
  , _sbom_dependencies :: Maybe [SBOMDependency]
  , _sbom_compositions :: Maybe [Composition]
  , _sbom_vulnerabilities :: Maybe [Vulnerability]
  , _sbom_annotations :: Maybe [Annotation]
  , _sbom_formulation :: Maybe [Formulation]
  , _sbom_properties :: Maybe [Property]
  , _sbom_signature :: Maybe Signature
  } deriving (Show, Generic)

type LifeCycle = Object
type Tool = Object
type Author = Object
type Manufacture = Object
type Supplier = Object
type License = Object

data MetaData = MetaData
  { _metadata_timestamp :: Maybe Text
  , _metadata_lifecycles :: Maybe [LifeCycle]
  , _metadata_tools :: Maybe [Tool]
  , _metadata_authors :: Maybe [Author]
  , _metadata_component :: Maybe Component
  , _metadata_manufacture :: Maybe Manufacture
  , _metadata_supplier :: Maybe Supplier
  , _metadata_licenses :: Maybe [License]
  , _metadata_properties :: Maybe [Property]
  } deriving (Show, Generic)

data Component = Component
  { _component_type :: Text
  , _component_mime_type :: Maybe Text
  , _component_bom_ref :: Maybe Text
  } deriving (Show, Generic)
