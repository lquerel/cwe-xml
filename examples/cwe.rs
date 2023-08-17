use std::io::Read;
use std::rc::Rc;

use cwe_xml::cwe::{CweDatabase, WeaknessVisitor};
use cwe_xml::cwe::weaknesses::Weakness;

/// Download the CWE catalogs, parse them, build a global CweCatalog struct and print it.
/// CWE files are zipped XML files.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cwe_db = CweDatabase::new();

    // Import the 3 main CWE catalogs from the official website.
    cwe_db.import_weakness_catalog_from_url("https://cwe.mitre.org/data/xml/views/699.xml.zip")?;
    cwe_db.import_weakness_catalog_from_url("https://cwe.mitre.org/data/xml/views/1000.xml.zip")?;
    cwe_db.import_weakness_catalog_from_url("https://cwe.mitre.org/data/xml/views/1194.xml.zip")?;

    cwe_db.infer_categories_from_ancestors();
    cwe_db.infer_categories_from_descendants();

    // Retrieve a weakness by its ID (CWE-73).
    let cwe_id: i64 = 306;
    let weakness = cwe_db.weakness_by_cwe_id(cwe_id);
    println!("Weakness CWE-ID-{}\n{:#?}", cwe_id, weakness);

    // Display the categories of the weakness (if any).
    let categories = cwe_db.categories_by_cwe_id(cwe_id);
    println!("Categories {:#?}", categories);

    let children = cwe_db.weakness_children_by_cwe_id(1076);
    println!("CWE-{} has {} children", cwe_id, children.len());

    println!("{} CWE roots", cwe_db.weakness_roots().len());
    for root in &cwe_db.weakness_roots() {
        println!("CWE-{} is a root '{}'", root.id, root.name);
    }

    let mut visitor = Visitor;

    cwe_db.visit_weaknesses(&mut visitor);

    // Display the CWE catalog summary.
    println!("{}", cwe_db);

    Ok(())
}

struct Visitor;

impl WeaknessVisitor for Visitor {
    fn visit(&mut self, db: &CweDatabase, level: usize, weakness: Rc<Weakness>) {
        let cats = db.categories_by_cwe_id(weakness.id).iter().map(|c| c.name.clone()).collect::<Vec<_>>();

        println!("{} CWE-{} {} (subtree-size: {}, categories: {:?})",
                 " ".repeat(level * 2),
                 weakness.id,
                 weakness.name,
                 db.weakness_subtree_by_cwe_id(weakness.id).len(),
                 cats
        );
    }
}