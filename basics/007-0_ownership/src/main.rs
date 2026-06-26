fn main() {

    // creation and reference to a pointer
    let a = Box::new([0;5]); // [0,0,0,0,0]
    let b = a; // reference to the pointer a  NOTE: the ownership of the data in the heap is transffered to be making a unusable
    //println!("this breaks things => {}",a[0]); // this breaks if uncommented 
    println!("this is fine => {}",b[0]); // this works fine


    // now if we don't want to transfer ownership and want to have 2 ref to the same data in heap we need to use .clone()
    let x = Box::new([0;5]); // [0,0,0,0,0]
    let y = x.clone(); // clone x in the heap to another array and y is a ref to that new array in the heap
    println!("this is fine => {}",x[0]); 
    println!("this is fine  too => {}",y[0]);


}
