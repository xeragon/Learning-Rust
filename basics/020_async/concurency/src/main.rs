use std::time::Duration;

fn main() {
    trpl::block_on(async {

    //    let handle = trpl::spawn_task(async {
    //         for i in 1..10 {
    //             println!("hi number {i} from the first task!");
    //             trpl::sleep(Duration::from_millis(500)).await;
    //         }
    //     });

    //     for i in 1..5 {
    //         println!("hi number {i} from the second task!");
    //         trpl::sleep(Duration::from_millis(500)).await;
    //     }

    //     handle.await.unwrap();

     //---------------------------------------------

        // let fut1 = async {
        //     for i in 1..10 {
        //         println!("hi number {i} from the first task!");
        //         trpl::sleep(Duration::from_millis(500)).await;
        //     }
        // };

        // let fut2 = async {
        //     for i in 1..5 {
        //         println!("hi number {i} from the second task!");
        //         trpl::sleep(Duration::from_millis(500)).await;
        //     }
        // };

        // trpl::join(fut1, fut2).await;

        //---------------------------------------------

        // let (tx, mut rx) = trpl::channel();

        // let tx_fut = async move {
        //     let vals = vec![
        //         String::from("hi"),
        //         String::from("from"),
        //         String::from("the"),
        //         String::from("future"),
        //     ];

        //     for val in vals {
        //         tx.send(val).unwrap();
        //         trpl::sleep(Duration::from_millis(500)).await;
        //     }
        // };

        // let rx_fut = async {
        //     while let Some(value) = rx.recv().await {
        //         println!("received '{value}'");
        //     }
        // };

        // trpl::join(tx_fut, rx_fut).await;

        // --------------------------------------
        
             let (tx, mut rx) = trpl::channel();

        let tx1 = tx.clone();
        let tx1_fut = async move {
            let vals = vec![
                String::from("hi"),
                String::from("from"),
                String::from("the"),
                String::from("future"),
            ];

            for val in vals {
                tx1.send(val).unwrap();
                trpl::sleep(Duration::from_millis(500)).await;
            }
        };

        let rx_fut = async {
            while let Some(value) = rx.recv().await {
                println!("received '{value}'");
            }
        };

        let tx_fut = async move {
            let vals = vec![
                String::from("more"),
                String::from("messages"),
                String::from("for"),
                String::from("you"),
            ];

            for val in vals {
                tx.send(val).unwrap();
                trpl::sleep(Duration::from_millis(1500)).await;
            }
        };

        trpl::join!(tx1_fut, tx_fut, rx_fut);
    });
    
}