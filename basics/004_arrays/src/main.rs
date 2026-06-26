fn main() {

    //tuples, can contain different types
    let x: (i32, f64, u8) = (500, 6.4, 1);
    let five_hundred = x.0;
    let six_point_four = x.1;
    let one = x.2;

    // array, unique type and fixed size, lives in the stack
    let y: [i32; 5] = [1, 2, 3, 4, 5];
    let y_autofill = [3; 5]; // produces [5,5,5]

    let first = y[0];
    let second = y[1];

    // vector, unique type, variable size, lives in the heap, described later
}
