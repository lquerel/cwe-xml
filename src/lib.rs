pub mod errors;
pub mod cwe;

#[cfg(test)]
mod tests {
    use crate::cwe::CweCatalog;

    #[test]
    fn from_file() {
        let cwe_db = match CweCatalog::from_file("data/1194.xml") {
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
