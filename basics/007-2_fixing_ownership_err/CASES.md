# Here are some exemples of Unsafe Programms, why they are and how to fix them

## Returning a Reference to the Stack
```rust
fn return_a_string() -> &String {
    let s = String::from("Hello world");
    &s
}
```

Here, the issue is with the lifetime of the referred data. If you want to pass around a reference to a string, you have to make sure that the underlying string lives long enough.

Depending on the situation, here are four ways you can extend the lifetime of the string : 
- One is to move ownership of the string out of the function, changing return type from &String to String:
- Another possibility is to return a string literal, which lives forever (indicated by 'static). This solution applies if we never intend to change the string, and then a heap allocation is unnecessary:
```rust 
    fn return_a_string() -> &'static str {
        "Hello world"    
    }
```
- Another possibility is to defer borrow-checking to runtime by using garbage collection. For example, you can use a reference-counted pointer:
```rust 
use std::rc::Rc;
fn return_a_string() -> Rc<String> {
    let s = Rc::new(String::from("Hello world"));
    Rc::clone(&s)
}
```
- Yet another possibility is to have the caller provide a “slot” to put the string using a mutable reference:
```rust 
fn return_a_string(output: &mut String) {
    output.replace_range(.., "Hello world");
}
```
With this strategy, the caller is responsible for creating space for the string. This style can be verbose, but it can also be more memory-efficient if the caller needs to carefully control when allocations occur.


## Not Enough Permissions
Let’s say we tried to write a function stringify_name_with_title. This function is supposed to create a person’s full name from a vector of name parts, including an extra title.

```rust
fn stringify_name_with_title(name: &Vec<String>) -> String {
    name.push(String::from("Esq."));
    let full = name.join(" ");
    full
}
```
This program is rejected by the borrow checker because name is an immutable reference, but name.push(..) requires the W permission. This program is unsafe because push could invalidate other references to name outside of stringify_name_with_title.

There are many possible fixes which vary in how much memory they use. One possibility is to clone the input name:
```rust
fn stringify_name_with_title(name: &Vec<String>) -> String {
    let mut name_clone = name.clone();
    name_clone.push(String::from("Esq."));
    let full = name_clone.join(" ");
    full
}
```

by cloning name, we are allowed to mutate the local copy of the vector. However, the clone copies every string in the input. We can avoid unnecessary copies by adding the suffix later:

```rust
fn stringify_name_with_title(name: &Vec<String>) -> String {
    let mut full = name.join(" ");
    full.push_str(" Esq.");
    full
}
```
This solution works because slice::join already copies the data in name into the string full.



# More
for the rest just read from [here](https://rust-book.cs.brown.edu/ch04-03-fixing-ownership-errors.html) if needed, why am I even copy pasting this doc ? 
