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

/// A CWE weakness database.
#[derive(Debug, Default)]
pub struct CweDatabase {
    catalogs: HashMap<String, WeaknessCatalog>,
    weakness_index: HashMap<i64, Rc<Weakness>>,
    category_index: HashMap<i64, HashMap<i64, Rc<categories::Category>>>,
}

impl CweDatabase {
    /// Create a new empty CWE database.
    pub fn new() -> CweDatabase {
        CweDatabase::default()
    }

    /// Import a CWE catalog from a string containing the XML.
    pub fn import_weakness_catalog_from_str(&mut self, xml: &str) -> Result<(), Error> {
        let weakness_catalog: WeaknessCatalog = quick_xml::de::from_str(xml).map_err(|e| Error::InvalidCweFile {
            file: "".to_string(),
            error: e.to_string(),
        })?;
        let catalog_name = weakness_catalog.name.clone();
        self.update_category_index(&weakness_catalog);
        self.update_weakness_index(&weakness_catalog);
        self.catalogs.insert(catalog_name, weakness_catalog);
        Ok(())
    }

    /// Import a CWE catalog from a file containing the XML.
    pub fn import_weakness_catalog_from_file(&mut self, xml_file: &str) -> Result<(), Error> {
        let file = File::open(xml_file).map_err(|e| Error::InvalidCweFile {
            file: xml_file.to_string(),
            error: e.to_string(),
        })?;
        let reader = BufReader::new(file);
        let weakness_catalog: WeaknessCatalog = quick_xml::de::from_reader(reader).map_err(|e| Error::InvalidCweFile {
            file: xml_file.to_string(),
            error: e.to_string(),
        })?;
        let catalog_name = weakness_catalog.name.clone();
        self.update_category_index(&weakness_catalog);
        self.update_weakness_index(&weakness_catalog);
        self.catalogs.insert(catalog_name, weakness_catalog);
        Ok(())
    }

    /// Import a CWE catalog from a reader containing the XML.
    pub fn import_weakness_catalog_from_reader<R>(&mut self, reader: R) -> Result<(), Error> where R: BufRead {
        let weakness_catalog: WeaknessCatalog = quick_xml::de::from_reader(reader).map_err(|e| Error::InvalidCweFile {
            file: "".to_string(),
            error: e.to_string(),
        })?;
        let catalog_name = weakness_catalog.name.clone();
        self.update_category_index(&weakness_catalog);
        self.update_weakness_index(&weakness_catalog);
        self.catalogs.insert(catalog_name, weakness_catalog);
        Ok(())
    }

    /// Returns a reference to a Weakness struct if the CWE-ID exists in the catalog.
    pub fn weakness_by_cwe_id(&self, cwe_id: i64) -> Option<Rc<Weakness>> {
        self.weakness_index.get(&cwe_id)
            .map(|weakness| weakness.clone())
    }

    /// Returns a list of categories for a given CWE-ID.
    pub fn categories_by_cwe_id(&self, cwe_id: i64) -> Option<Vec<Rc<categories::Category>>> {
        self.category_index.get(&cwe_id)
            .map(|categories| categories.values().cloned().collect())
    }

    fn update_weakness_index(&mut self, catalog: &WeaknessCatalog) {
        if let Some(catalog) = &catalog.weaknesses {
            for weakness in catalog.weaknesses.iter() {
                self.weakness_index.insert(weakness.id, weakness.clone());
            }
        }
    }

    fn update_category_index(&mut self, catalog: &WeaknessCatalog) {
        if let Some(categories) = &catalog.categories {
            for category in categories.categories.iter() {
                for member in &category.relationships.has_members {
                    self.category_index.entry(member.cwe_id).or_insert_with(HashMap::new).insert(category.id, category.clone());
                }
            }
        }
    }
}

impl Display for CweDatabase {
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