{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}


module LocalSecurityScanner.SBOM where

import LocalSecurityScanner.Utils
import Data.Aeson.TH

import GHC.Generics
import Data.Aeson
import Data.Text (Text)

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
  , _sbom_version :: Integer
  , _sbom_metadata :: Maybe MetaData
  , _sbom_components :: Maybe [Component]
  , _sbom_services :: Maybe [Service]
  , _sbom_externalReferences :: Maybe [SBOMReference]
  , _sbom_dependencies :: Maybe [SBOMDependency]
  } deriving (Show, Generic)

data SBOMReference = SBOMReference
  { _sbomreference_url :: Text
  , _sbomreference_comment :: Maybe Text
  , _sbomreference_type :: Text
  } deriving (Show, Generic)

data SBOMDependency = SBOMDependency
  { _sbomdependency_ref :: Text
  , _sbomdependency_dependsOn :: Maybe [Text]
  } deriving (Show, Generic)

data Service = Service
  { _service_bom_ref :: Maybe Text
  , _service_proivder :: Maybe Provider
  , _service_group :: Maybe Text
  , _service_name :: Text
  , _service_version :: Maybe Text
  , _service_description :: Maybe Text
  , _service_endpoints :: Maybe Text
  , _service_authenticated :: Maybe Bool
  , _service_x_trust_boundary :: Maybe Bool
  , _service_data :: Maybe [SBOMData]
  , _service_license :: Maybe [License]
  , _service_externalReferences :: Maybe [Reference]
  , _service_services :: Maybe [Service]
  } deriving (Show, Generic)

data SBOMData = ServiceData
  { _servicedata_flow :: Text
  , _servicedata_classification :: Text
  } deriving (Show, Generic)

type Provider = Supplier

type LifeCycle = Object
type Tool = Object
type Author = Object
type Manufacture = Object
type Pedigree = Object
type Reference = SBOMReference
type Evidence = Object
type ReleaseNote = Object
type ModelCard = Object
type Data = Object
type Properties = Object

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
  , _component_supplier :: Maybe Supplier
  , _component_author :: Maybe Text
  , _component_publisher :: Maybe Text
  , _component_group :: Maybe Text
  , _component_name :: Maybe Text
  , _component_version :: Maybe Text
  , _component_description :: Maybe Text
  , _component_scope :: Maybe Text
  , _component_hashes :: Maybe [Hash]
  , _component_licenses :: Maybe [License]
  , _component_copyright :: Maybe Text
  , _component_cpe :: Maybe Text
  , _component_purl :: Maybe Text
  , _component_swid :: Maybe SWID
  , _component_modified :: Maybe Bool
  , _component_pedigree :: Maybe Pedigree
  , _component_externalReferences :: Maybe Reference
  , _component_components :: Maybe [Component]
  , _component_evidence :: Maybe Evidence
  , _component_releaseNotes :: Maybe ReleaseNote
  , _component_modelCard :: Maybe ModelCard
  , _component_data :: Maybe [Data]
  , _component_properties :: Maybe [Properties]
  , _component_signature :: Maybe [Signature]
  } deriving (Show, Generic)

data Supplier = Supplier
  { _supplier_name :: Maybe Text
  , _supplier_url :: Maybe Text
  , _supplier_contact :: Maybe Contact
  } deriving (Show, Generic)

data Contact = Contact
  { _contact_name :: Maybe Text
  , _contact_email :: Maybe Text
  , _contact_phone :: Maybe Text
  } deriving (Show, Generic)

data Hash = Hash
 { _hash_alg :: Text
 , _hash_content :: Text
 } deriving (Show, Generic)

data License = License
 { _license_license :: Maybe LicenseData
 , _license_expression :: Maybe Text
 } deriving (Show, Generic)

data LicenseData = LicenseData
  { _licensedata_id :: Maybe Text
  , _licensedata_name :: Maybe Text
  , _licensedata_text :: Maybe [SBOMText]
  , _licensedata_url :: Maybe Text
  } deriving (Show, Generic)

data SBOMText = SBOMText
  { _sbomtext_contentType :: Maybe Text
  , _sbomtext_encoding :: Maybe Text
  , _sbomtext_content :: Text
  } deriving (Show, Generic)

data SWID = SWID
  { _swid_tagId :: Text
  , _swid_name :: Text
  , _swid_version :: Maybe Text
  , _swid_tagVersion :: Maybe Text
  , _swid_patch :: Maybe Text
  , _swid_text :: Maybe SBOMText
  , _swid_url :: Maybe Text
  } deriving (Show, Generic)

mconcat <$> sequence (deriveJSON stripType' <$>
    [ ''SBOM
    , ''MetaData
    , ''Component
    , ''Supplier
    , ''Contact
    , ''Hash
    , ''License
    , ''LicenseData
    , ''SBOMText
    , ''SWID
    , ''SBOMDependency
    , ''SBOMReference
    , ''Service
    , ''SBOMData
    ])

parseSBOM :: String -> IO (Maybe SBOM)
parseSBOM fp = do
    decodeFileStrict fp :: IO (Maybe SBOM)
