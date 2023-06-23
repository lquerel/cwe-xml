use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::id;
use std::rc::Rc;

use crate::cwe::categories::Category;
use crate::cwe::weakness_catalog::WeaknessCatalog;
use crate::cwe::weaknesses::{RelatedNature, Weakness};
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
    cwe_categories_index: HashMap<i64 /*cwe-id*/, HashSet<Rc<Category>>>,
    weakness_children_index: HashMap<i64, HashSet<Rc<Weakness>>>,
    weakness_roots_index: HashMap<i64, Rc<Weakness>>,
}

pub trait WeaknessVisitor {
    fn visit(&mut self, db: &CweDatabase, level: usize, weakness: Rc<Weakness>);
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
        self.update_indexes(&weakness_catalog);
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
        self.update_indexes(&weakness_catalog);
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
        self.update_indexes(&weakness_catalog);
        self.catalogs.insert(catalog_name, weakness_catalog);
        Ok(())
    }

    /// Returns a reference to a Weakness struct if the CWE-ID exists in the catalog.
    pub fn weakness_by_cwe_id(&self, cwe_id: i64) -> Option<Rc<Weakness>> {
        self.weakness_index.get(&cwe_id)
            .map(|weakness| weakness.clone())
    }

    /// Returns a list of categories for a given CWE-ID.
    pub fn categories_by_cwe_id(&self, cwe_id: i64) -> HashSet<Rc<Category>> {
        self.cwe_categories_index.get(&cwe_id)
            .map(|categories| categories.clone())
            .unwrap_or_default()
    }

    /// Returns a list of weaknesses that are children of a given CWE-ID.
    pub fn weakness_children_by_cwe_id(&self, cwe_id: i64) -> HashSet<Rc<Weakness>> {
        self.weakness_children_index.get(&cwe_id)
            .map(|weaknesses| weaknesses.clone())
            .unwrap_or_default()
    }

    /// Returns a list of weaknesses that are children of a given CWE-ID.
    /// The list does not contain the weakness for the given CWE-ID.
    pub fn weakness_subtree_by_cwe_id(&self, cwe_id: i64) -> Vec<Rc<Weakness>> {
        let mut visitor = CweIdSubTreeVisitor::default();

        if let Some(weakness) = self.weakness_by_cwe_id(cwe_id) {
            self.visit_weakness(&mut visitor, 0, &weakness);
        }

        if visitor.cwe_ids.is_empty() {
            vec![]
        } else {
            visitor.cwe_ids.iter().map(|cwe_id| self.weakness_by_cwe_id(*cwe_id).expect("should never happen")).collect()
        }
    }

    /// Returns a list of weaknesses that are roots, i.e. they have no parents.
    pub fn weakness_roots(&self) -> HashSet<Rc<Weakness>> {
        self.weakness_roots_index.values().cloned().collect()
    }

    /// Visit all root weaknesses in the database and their children.
    pub fn visit_weaknesses(&self, visitor: &mut impl WeaknessVisitor) {
        for weakness in self.weakness_roots().iter() {
            self.visit_weakness(visitor, 0, weakness);
        }
    }

    /// Returns the direct weakness ancestors of a given CWE-ID.
    pub fn direct_ancestors_by_cwe_id(&self, cwe_id: i64) -> HashSet<Rc<Weakness>> {
        let mut ancestors = HashSet::new();
        if let Some(weakness) = self.weakness_by_cwe_id(cwe_id) {
            for ancestor_id in weakness.direct_ancestors() {
                if let Some(ancestor) = self.weakness_by_cwe_id(ancestor_id) {
                    ancestors.insert(ancestor);
                }
            }
        }
        ancestors
    }

    /// Merge the given categories into the category index for the given CWE-ID.
    pub fn merge_categories_by_cwe_id(&mut self, cwe_id: i64, categories: HashSet<Rc<Category>>) {
        self.cwe_categories_index.entry(cwe_id).or_insert_with(HashSet::new).extend(categories.iter().cloned());
    }

    /// Returns a list of all categories in the database (across all catalogs).
    pub fn all_categories(&self) -> HashSet<Rc<Category>> {
        let mut categories = HashSet::new();
        for catalog in self.catalogs.values() {
            if let Some(cats) = catalog.categories.as_ref() {
                categories.extend(cats.categories.iter().cloned());
            }
        }
        categories
    }

    /// Sub-weaknesses inherit the categories of their parent weaknesses.
    pub fn infer_categories_from_ancestors(&mut self) {
        let mut inferred_categories = HashMap::new();
        let category_index = self.cwe_categories_index.clone();
        for (cwe_id, categories) in category_index.iter() {
            self.propagate_categories_to_subtree(*cwe_id, categories.clone(), &mut inferred_categories);
        }

        for (cwe_id, categories) in inferred_categories {
            self.cwe_categories_index.entry(cwe_id).or_insert_with(HashSet::new).extend(categories.iter().cloned());
        }
    }

    /// Propagate categories to ancestors that don't have any categories yet and have only one child
    /// that has no category defined.
    /// This is a heuristic to infer categories for weaknesses that have no categories defined.
    /// This process is repeated until no more categories can be propagated.
    pub fn infer_categories_from_descendants(&mut self) {
        struct PropagatedCategories {
            categories: HashSet<Rc<Category>>,
            no_category_count: usize,
        }

        loop {
            // Number of updates in the current round
            let mut update_count = 0;
            let mut propagated_categories = HashMap::new();

            for (id, weakness) in self.weakness_index.iter() {
                let categories = self.categories_by_cwe_id(*id);

                let ancestors = self.direct_ancestors_by_cwe_id(*id);
                for ancestor in ancestors.iter() {
                    let ancestor_cats = self.categories_by_cwe_id(ancestor.id);
                    if !ancestor_cats.is_empty() {
                        // skip ancestors that already have categories
                        continue;
                    }
                    let propagated_categories = propagated_categories.entry(ancestor.id).or_insert_with(|| PropagatedCategories {
                        categories: HashSet::new(),
                        no_category_count: 0,
                    });
                    if categories.is_empty() {
                        propagated_categories.no_category_count += 1;
                    } else {
                        propagated_categories.categories.extend(categories.iter().cloned());
                    }
                }
            }

            for (cwe_id, categories) in propagated_categories {
                if categories.no_category_count <= 1 {
                    let mut existing_cats = self.cwe_categories_index.entry(cwe_id).or_insert_with(HashSet::new);
                    let existing_cats_count = existing_cats.len();
                    existing_cats.extend(categories.categories.iter().cloned());
                    if existing_cats.len() > existing_cats_count {
                        update_count += 1;
                    }
                }
            }

            if update_count == 0 {
                break;
            }
        }
    }

    fn propagate_categories_to_subtree(&self, cwe_id: i64, categories: HashSet<Rc<Category>>, inferred_categories: &mut HashMap<i64, HashSet<Rc<Category>>>) {
        inferred_categories.entry(cwe_id).or_insert_with(HashSet::new).extend(categories.iter().cloned());
        let categories = inferred_categories.get(&cwe_id).expect("Should never happen").clone();

        let children = self.weakness_children_by_cwe_id(cwe_id);
        for child in children.iter() {
            self.propagate_categories_to_subtree(child.id, categories.clone(), inferred_categories);
        }
    }

    fn visit_weakness(&self, visitor: &mut impl WeaknessVisitor, level: usize, weakness: &Rc<Weakness>) {
        visitor.visit(self, level, weakness.clone());
        for child in self.weakness_children_by_cwe_id(weakness.id).iter() {
            self.visit_weakness(visitor, level + 1, child);
        }
    }

    fn update_indexes(&mut self, catalog: &WeaknessCatalog) {
        self.update_category_index(catalog);
        self.update_weakness_index(catalog);
        self.update_weakness_children_index(catalog);
    }

    fn update_weakness_index(&mut self, catalog: &WeaknessCatalog) {
        if let Some(catalog) = &catalog.weaknesses {
            for weakness in catalog.weaknesses.iter() {
                self.weakness_index.insert(weakness.id, weakness.clone());
            }
        }
    }

    fn update_weakness_children_index(&mut self, catalog: &WeaknessCatalog) {
        if let Some(catalog) = &catalog.weaknesses {
            for weakness in catalog.weaknesses.iter() {
                let mut parent_count = 0;
                if let Some(related_weaknesses) = &weakness.related_weaknesses {
                    for related_weakness in &related_weaknesses.related_weaknesses {
                        if related_weakness.nature == RelatedNature::ChildOf {
                            self.weakness_children_index.entry(related_weakness.cwe_id).or_insert_with(HashSet::new).insert(weakness.clone());
                            parent_count += 1;
                        }
                    }
                }

                if parent_count == 0 {
                    self.weakness_roots_index.insert(weakness.id, weakness.clone());
                }
            }
        }
    }

    fn update_category_index(&mut self, catalog: &WeaknessCatalog) {
        if let Some(categories) = &catalog.categories {
            for category in categories.categories.iter() {
                for member in &category.relationships.has_members {
                    self.cwe_categories_index.entry(member.cwe_id).or_insert_with(HashSet::new).insert(category.clone());
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

#[derive(Default)]
struct CweIdSubTreeVisitor {
    cwe_ids: HashSet<i64>,
}

impl WeaknessVisitor for CweIdSubTreeVisitor {
    fn visit(&mut self, _: &CweDatabase, level: usize, weakness: Rc<Weakness>) {
        if level > 0 {
            self.cwe_ids.insert(weakness.id);
        }
    }
}