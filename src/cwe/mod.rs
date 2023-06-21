use std::fs::File;
use std::io::{BufRead, BufReader};
use crate::cwe::weakness_catalog::WeaknessCatalog;
use crate::errors::Error;

pub mod views;
pub mod external_references;
pub mod weaknesses;
pub mod categories;
pub mod relationships;
pub mod notes;
pub mod content_history;
pub mod structured_text;
pub mod weakness_catalog;

#[derive(Debug)]
pub struct CweCatalog {
    pub weakness_catalog: WeaknessCatalog,
}

impl CweCatalog {
    pub fn from_str(xml: &str) -> Result<CweCatalog, Error> {
        let weakness_catalog: WeaknessCatalog = quick_xml::de::from_str(xml).map_err(|e| Error::InvalidCweFile {
            file: "".to_string(),
            error: e.to_string(),
        })?;
        Ok(CweCatalog { weakness_catalog })
    }

    pub fn from_file(xml_file: &str) -> Result<CweCatalog, Error> {
        let file = File::open(xml_file).map_err(|e| Error::InvalidCweFile {
            file: xml_file.to_string(),
            error: e.to_string(),
        })?;
        let reader = BufReader::new(file);
        let weakness_catalog: WeaknessCatalog = quick_xml::de::from_reader(reader).map_err(|e| Error::InvalidCweFile {
            file: xml_file.to_string(),
            error: e.to_string(),
        })?;
        Ok(CweCatalog { weakness_catalog })
    }

    pub fn from_reader<R>(reader: R) -> Result<CweCatalog, Error> where R: BufRead {
        let weakness_catalog: WeaknessCatalog = quick_xml::de::from_reader(reader).map_err(|e| Error::InvalidCweFile {
            file: "".to_string(),
            error: e.to_string(),
        })?;
        Ok(CweCatalog { weakness_catalog })
    }
}
