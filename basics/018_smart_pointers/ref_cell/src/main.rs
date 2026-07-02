use std::cell::RefCell;
use std::rc::Rc;

// Trait for sending messages
trait Messenger {
    fn send(&self, msg: &str);
}

// Mock object using RefCell for interior mutability
struct MockMessenger {
    sent_messages: RefCell<Vec<String>>,
}

impl MockMessenger {
    fn new() -> Self {
        MockMessenger {
            sent_messages: RefCell::new(vec![]),
        }
    }
}

impl Messenger for MockMessenger {
    fn send(&self, message: &str) {
        // Mutate internal state even with &self
        self.sent_messages.borrow_mut().push(message.to_string());
    }
}

fn main() {
    // Example 1: Basic RefCell usage
    let x = RefCell::new(42);
    *x.borrow_mut() = 10; // Mutate through immutable reference
    println!("RefCell: {}", *x.borrow());

    // Example 2: RefCell + Rc for shared mutability
    let value = Rc::new(RefCell::new(5));
    let a = Rc::clone(&value);
    *a.borrow_mut() += 10; // Mutate through Rc
    println!("Rc<RefCell>: {}", *value.borrow());

    // Example 3: Mock object in action
    let mock = MockMessenger::new();
    mock.send("Hello");
    println!("Mock messages: {:?}", *mock.sent_messages.borrow());
}