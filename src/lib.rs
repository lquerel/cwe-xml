use std::fmt::Debug;
use std::fs::File;
use std::io::BufReader;

use serde::Deserialize;
use categories::Categories;
use external_references::ExternalReferences;
use views::Views;
use weaknesses::{Weaknesses};

use crate::errors::Error;

pub mod errors;
pub mod views;
pub mod external_references;
pub mod weaknesses;
pub mod categories;
pub mod relationships;
pub mod notes;
pub mod content_history;
pub mod structured_text;

#[derive(Debug, Deserialize)]
#[serde(rename = "Weakness_Catalog")]
pub struct WeaknessCatalog {
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Version")]
    pub version: String,
    #[serde(rename = "@Date")]
    pub date: String,
    #[serde(rename = "Weaknesses")]
    pub weaknesses: Option<Weaknesses>,
    #[serde(rename = "Categories")]
    pub categories: Option<Categories>,
    #[serde(rename = "Views")]
    pub views: Option<Views>,
    #[serde(rename = "External_References")]
    pub external_references: Option<ExternalReferences>,
}

#[derive(Debug)]
pub struct CweDb {
    weakness_catalog: WeaknessCatalog,
}

impl CweDb {
    pub fn from_file(xml_file: &str) -> Result<CweDb, Error> {
        let file = File::open(xml_file).map_err(|e| Error::InvalidCweFile {
            file: xml_file.to_string(),
            error: e.to_string(),
        })?;
        let reader = BufReader::new(file);
        let weakness_catalog: WeaknessCatalog = quick_xml::de::from_reader(reader).map_err(|e| Error::InvalidCweFile {
            file: xml_file.to_string(),
            error: e.to_string(),
        })?;
        Ok(CweDb { weakness_catalog })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_file() {
        let cwe_db = match CweDb::from_file("data/699.xml") {
            Ok(cwe_db) => cwe_db,
            Err(e) => {
                panic!("Error: {:?}", e)
            }
        };
        // format debug output
        let output = format!("{:#?}", cwe_db);
        println!("{}", output);
    }
}
