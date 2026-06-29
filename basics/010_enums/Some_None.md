Rust does not have nulls, but it does have an enum that can encode the concept of a value being present or absent. This enum is Option<T>, and it is defined by the standard library as follows:

```rust
enum Option<T> {
    None,
    Some(T),
}
```

The Option<T> enum is so useful that it’s even included in the prelude; you don’t need to bring it into scope explicitly. Its variants are also included in the prelude: You can use Some and None directly without the Option:: prefix. The Option<T> enum is still just a regular enum, and Some(T) and None are still variants of type Option<T>.

The <T> syntax is a generic type parameter, <T> means that the Some variant of the Option enum can hold one piece of data of any type, and that each concrete type that gets used in place of T makes the overall Option<T> type a different type. Here are some examples of using Option values to hold number types and char types:
```rust
let some_number = Some(5);
let some_char = Some('e');

let absent_number: Option<i32> = None;
```