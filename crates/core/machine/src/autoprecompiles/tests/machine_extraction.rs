use std::{fs, io, path::Path};

use itertools::Itertools;
use pretty_assertions::assert_eq;
use slop_baby_bear::SP1Field;

use crate::{
    autoprecompiles::{bus_map::sp1_bus_map, instruction_handler::Sp1InstructionHandler},
    utils::setup_logger,
};

#[test]
fn test_extract_machine() {
    setup_logger();
    let instruction_handler = Sp1InstructionHandler::<SP1Field>::new();
    let airs = instruction_handler.airs();
    let rendered = airs
        .map(|(instruction_type, air)| {
            format!("# {instruction_type:?}\n{}", air.render(&sp1_bus_map()))
        })
        .join("\n\n\n");

    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("extracted_constraints.txt");
    match fs::read_to_string(&path) {
        // Snapshot exists, compare it with the extracted constraints
        Ok(expected) => {
            assert_eq!(rendered, expected)
        }

        // Snapshot does not exist, create it
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, &rendered).unwrap();
            panic!("Created new snapshot at {path:?}. Inspect it, then rerun the tests.");
        }

        Err(_) => panic!(),
    }
}
