use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::rc::Rc;
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
    catalogs: HashMap<String, WeaknessCatalog>,
    weakness_by_id: HashMap<i64, Rc<Weakness>>,
}

impl CweCatalog {
    pub fn new() -> CweCatalog {
        CweCatalog {
            catalogs: HashMap::new(),
            weakness_by_id: HashMap::new(),
        }
    }

    /// Build a CweCatalog from an XML string containing the CWE catalog.
    pub fn import_weakness_catalog_from_str(&mut self, xml: &str) -> Result<(), Error> {
        let mut weakness_catalog: WeaknessCatalog = quick_xml::de::from_str(xml).map_err(|e| Error::InvalidCweFile {
            file: "".to_string(),
            error: e.to_string(),
        })?;
        let catalog_name = weakness_catalog.name.clone();
        CweCatalog::update_weakness_categories(&mut weakness_catalog);
        self.build_cwe_id_to_weakness(&weakness_catalog);
        self.catalogs.insert(catalog_name, weakness_catalog);
        Ok(())
    }

    /// Build a CweCatalog from an XML file containing the CWE catalog.
    pub fn import_weakness_catalog_from_file(&mut self, xml_file: &str) -> Result<(), Error> {
        let file = File::open(xml_file).map_err(|e| Error::InvalidCweFile {
            file: xml_file.to_string(),
            error: e.to_string(),
        })?;
        let reader = BufReader::new(file);
        let mut weakness_catalog: WeaknessCatalog = quick_xml::de::from_reader(reader).map_err(|e| Error::InvalidCweFile {
            file: xml_file.to_string(),
            error: e.to_string(),
        })?;
        let catalog_name = weakness_catalog.name.clone();
        CweCatalog::update_weakness_categories(&mut weakness_catalog);
        self.build_cwe_id_to_weakness(&weakness_catalog);
        self.catalogs.insert(catalog_name, weakness_catalog);
        Ok(())
    }

    /// Build a CweCatalog from a BufRead containing the CWE catalog.
    pub fn import_weakness_catalog_from_reader<R>(&mut self, reader: R) -> Result<(), Error> where R: BufRead {
        let mut weakness_catalog: WeaknessCatalog = quick_xml::de::from_reader(reader).map_err(|e| Error::InvalidCweFile {
            file: "".to_string(),
            error: e.to_string(),
        })?;
        let catalog_name = weakness_catalog.name.clone();
        CweCatalog::update_weakness_categories(&mut weakness_catalog);
        self.build_cwe_id_to_weakness(&weakness_catalog);
        self.catalogs.insert(catalog_name, weakness_catalog);
        Ok(())
    }

    /// Returns a reference to a Weakness struct if the CWE-ID exists in the catalog.
    pub fn weakness_by_id(&self, cwe_id: i64) -> Option<Rc<Weakness>> {
        self.weakness_by_id.get(&cwe_id).map(|weakness| weakness.clone())
    }

    fn build_cwe_id_to_weakness(&mut self, catalog: &WeaknessCatalog) {
        if let Some(catalog) = &catalog.weaknesses {
            for weakness in catalog.weaknesses.iter() {
                self.weakness_by_id.insert(weakness.id, weakness.clone());
            }
        }
    }

    fn update_weakness_categories(catalog: &mut WeaknessCatalog) {
        let mut cwe_categories = HashMap::new();

        if let Some(categories) = &catalog.categories {
            for category in categories.categories.iter() {
                for member in &category.relationships.has_members {
                    cwe_categories.entry(member.cwe_id).or_insert_with(Vec::new).push(category.clone());
                }
            }
        }

        for weakness in &mut catalog.weaknesses.as_mut().unwrap().weaknesses {
            if let Some(categories) = cwe_categories.remove(&weakness.id) {
                let w = Rc::get_mut(weakness).unwrap();
                w.categories.replace(categories);
            }
        }
    }
}

impl Display for CweCatalog {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut text = String::new();
        for (catalog_name, catalog) in &self.catalogs {
            text.push_str(&format!("Catalog: {}\n", catalog_name));
            text.push_str(&format!("  Version: {}\n", catalog.version));
            text.push_str(&format!("  Date: {}\n", catalog.date));
            text.push_str(&format!("  #Weaknesses: {}\n", catalog.weaknesses.as_ref().unwrap().weaknesses.len()));
        }
        write!(f, "{}", text)
    }
}