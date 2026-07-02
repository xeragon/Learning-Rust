enum List {
    Cons(i32, Box<List>), // fixes the infinite size calculation durging compilation that would occur with Cons(i32, List),
    Nil,
}

use crate::List::{Cons, Nil};

fn main() {
    let list = Cons(1, Box::new(Cons(2, Box::new(Cons(3, Box::new(Nil))))));
}

// size of a pointer on 64 bits system is 8 bytes
// dereference to acess value works as usual with '*'