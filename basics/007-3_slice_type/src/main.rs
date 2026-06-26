fn main() {
    //A string slice is a reference to part of a String, and it looks like this:
    let s = String::from("hello world");

    let hello: &str = &s[0..5];
    let world: &str = &s[6..11];
    let s2: &String = &s;

    // those two syntaxes do the same thing
    let slice = &s[0..2];
    let slice = &s[..2];
    
    let len = s.len();
    // those two syntaxes do the same thing
    let slice = &s[3..len];
    let slice = &s[3..];
}

fn first_word(s: &String) -> &str {
    let bytes = s.as_bytes();

    for (i, &item) in bytes.iter().enumerate() {
        if item == b' ' {
            return &s[0..i];
        }
    }

    &s[..]
}
