fn a_function(x: u32, y: char) {
    println!("A function. x = {} y = {}", x, y);
}

fn five() -> i32 {
    5 // <- no semicolon for a return value
}

fn main() {
    println!("Hello, world!");

    a_function(5,'g');

    another_function();

    println!("{}",five());
}

fn another_function() {
    println!("Another function.");
}

