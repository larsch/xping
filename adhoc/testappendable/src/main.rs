use xping::display::appendable::AppendableDisplay;

fn main() {
    // create a display of 10 rows
    let mut display = AppendableDisplay::new(10);

    // fill all rows
    for i in 0..10 {
        display.create(&format!("Row {}", i)).unwrap();
    }

    // when updating the rows, the first one will (currently) not be updates, as
    // it has been scrolled off the screen (could be fixed)
    for i in 0..10 {
        display.append(i, &format!("Append {}", i)).unwrap();
    }
}
