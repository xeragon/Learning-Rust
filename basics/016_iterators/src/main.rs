fn main() {
    println!("Test {}", iterator_sum());
}

fn iterator_sum() -> i32 {
    let v1 = vec![1, 2, 3];
    v1.iter().sum()
}

//usage of filter and map to customize iterator is pretty similar to javascript
// map and filter take a closure (anonymous function basicaly) as a param just like js 