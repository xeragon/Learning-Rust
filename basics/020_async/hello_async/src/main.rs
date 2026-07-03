// use trpl::Html;

// async fn page_title(url: &str) -> Option<String> {
//     let response = trpl::get(url).await;
//     let response_text = response.text().await;
//     // let response_text = trpl::get(url).await.text().await; // this works too
//     Html::parse(&response_text)
//         .select_first("title")
//         .map(|title| title.inner_html())
// }




use std::future::Future;
use trpl::{Either, Html};

// fn main() {
//  let args: Vec<String> = std::env::args().collect();

//     trpl::block_on(async {
//         let url = &args[1];
//         match page_title(url).await {
//             Some(title) => println!("The title for {url} was {title}"),
//             None => println!("{url} had no title"),
//         }
//     })
// }

// fn page_title(url: &str) -> impl Future<Output = Option<String>> {
//     async move {
//         let text = trpl::get(url).await.text().await;
//         Html::parse(&text)
//             .select_first("title")
//             .map(|title| title.inner_html())
//     }
// }


fn main() {
    let args: Vec<String> = std::env::args().collect();

    trpl::block_on(async {
        let title_fut_1 = page_title(&args[1]);
        let title_fut_2 = page_title(&args[2]);

        let (url, maybe_title) =
            match trpl::select(title_fut_1, title_fut_2).await {
                Either::Left(left) => left,
                Either::Right(right) => right,
            };

        println!("{url} returned first");
        match maybe_title {
            Some(title) => println!("Its page title was: '{title}'"),
            None => println!("It had no title."),
        }
    })
}

async fn page_title(url: &str) -> (&str, Option<String>) {
    let response_text = trpl::get(url).await.text().await;
    let title = Html::parse(&response_text)
        .select_first("title")
        .map(|title| title.inner_html());
    (url, title)
}