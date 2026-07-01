fn main() {
    let mut list = vec![1, 2, 3];
    println!("Before defining closure: {list:?}");
    
    let mut borrows_mutably = || (list.push(7), println!("In closure: {list:?}") );
    
    // println!("Before calling closure: {list:?}"); // this would cause panic because of immutable borrow before a mutable borrow
    borrows_mutably();
    println!("After calling closure: {list:?}");
}

// cant have two main func obviously dont forget to comment one another to test individually

#[derive(Debug)]
struct Rectangle {
    width: u32,
    height: u32,
}

fn main() {
    let mut list = [
        Rectangle { width: 10, height: 1 },
        Rectangle { width: 3, height: 5 },
        Rectangle { width: 7, height: 12 },
    ];

    let mut num_sort_operations = 0;
    list.sort_by_key(|r| {
        num_sort_operations += 1;
        r.width
    });
    println!("{list:#?}, sorted in {num_sort_operations} operations");
}