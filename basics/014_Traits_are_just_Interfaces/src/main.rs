// exemple generer avec Mistral

// Définition du trait avec une méthode par défaut
trait Saluer {
    // Méthode avec implémentation par défaut
    fn dire_bonjour(&self) -> String {
        "Bonjour, inconnu !".to_string()
    }

    // Méthode sans implémentation par défaut (obligatoire à implémenter)
    fn dire_au_revoir(&self) -> String;
}

// Implémentation pour `Personne` :
// - Utilise la méthode par défaut pour `dire_bonjour`
// - Implémente `dire_au_revoir` (obligatoire)
struct Personne {
    nom: String,
}
impl Saluer for Personne {
    fn dire_au_revoir(&self) -> String {
        format!("Au revoir, {} !", self.nom)
    }
    // Pas besoin d'implémenter `dire_bonjour` : on utilise la version par défaut.
}

// Implémentation pour `i32` :
// - Surcharge `dire_bonjour` (remplace la version par défaut)
// - Implémente `dire_au_revoir`
impl Saluer for i32 {
    fn dire_bonjour(&self) -> String {
        format!("Bonjour, nombre {} !", self)
    }

    fn dire_au_revoir(&self) -> String {
        format!("Au revoir, nombre {} !", self)
    }
}

// Fonction générique qui utilise le trait
fn interagir<T: Saluer>(qui: T) {
    println!("{}", qui.dire_bonjour());
    println!("{}", qui.dire_au_revoir());
}

fn main() {
    let alice = Personne {
        nom: "Alice".to_string(),
    };
    interagir(alice);
    // Affiche :
    // Bonjour, inconnu ! (version par défaut)
    // Au revoir, Alice !

    interagir(42);
    // Affiche :
    // Bonjour, nombre 42 ! (version surchargée)
    // Au revoir, nombre 42 !
}
