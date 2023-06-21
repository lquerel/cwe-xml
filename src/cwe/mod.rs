use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use crate::cwe::weakness_catalog::WeaknessCatalog;
use crate::cwe::weaknesses::Weakness;
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
    cwe_id_to_index: HashMap<i64, usize>,
}

impl CweCatalog {
    /// Build a CweCatalog from an XML string containing the CWE catalog.
    pub fn from_str(xml: &str) -> Result<CweCatalog, Error> {
        let weakness_catalog: WeaknessCatalog = quick_xml::de::from_str(xml).map_err(|e| Error::InvalidCweFile {
            file: "".to_string(),
            error: e.to_string(),
        })?;
        let cwe_id_to_index = CweCatalog::build_cwe_id_to_index(&weakness_catalog);
        Ok(CweCatalog { weakness_catalog, cwe_id_to_index })
    }

    /// Build a CweCatalog from an XML file containing the CWE catalog.
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
        let cwe_id_to_index = CweCatalog::build_cwe_id_to_index(&weakness_catalog);
        Ok(CweCatalog { weakness_catalog, cwe_id_to_index })
    }

    /// Build a CweCatalog from a BufRead containing the CWE catalog.
    pub fn from_reader<R>(reader: R) -> Result<CweCatalog, Error> where R: BufRead {
        let weakness_catalog: WeaknessCatalog = quick_xml::de::from_reader(reader).map_err(|e| Error::InvalidCweFile {
            file: "".to_string(),
            error: e.to_string(),
        })?;
        let cwe_id_to_index = CweCatalog::build_cwe_id_to_index(&weakness_catalog);
        Ok(CweCatalog { weakness_catalog, cwe_id_to_index })
    }

    /// Returns a reference to a Weakness struct if the CWE-ID exists in the catalog.
    pub fn weakness_by_cwe_id(&self, cwe_id: i64) -> Option<&Weakness> {
        if let Some(index) = self.cwe_id_to_index.get(&cwe_id) {
            if let Some(weaknesses) = &self.weakness_catalog.weaknesses {
                return weaknesses.weaknesses.get(*index);
            }
        }
        None
    }

    fn build_cwe_id_to_index(catalog: &WeaknessCatalog) -> HashMap<i64, usize> {
        let mut cwe_id_to_index = HashMap::new();
        if let Some(catalog) = &catalog.weaknesses {
            for (index, weakness) in catalog.weaknesses.iter().enumerate() {
                cwe_id_to_index.insert(weakness.id, index);
            }
        }
        cwe_id_to_index
    }
}
