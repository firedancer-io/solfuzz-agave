/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use index_list::IndexList;

fn main() {
    let name = "IndexList";
    let mut list = IndexList::<String>::from(
        &mut vec!["Hello,".into(), "world!".into()]);
    let index = list.insert_last(name.to_string());
    list.insert_before(index, String::from("I"));
    list.insert_before(index, String::from("am"));
    let parts: Vec<&str> = list.iter().map(|e| e.as_ref()).collect();
    println!("{}.", parts.join(" "));
    let mut index = list.first_index();
    while index.is_some() {
        list.get_mut(index).map(|s| {
            if s.chars().last().unwrap().is_ascii_punctuation() {
                *s = s.get(0..s.len()-1).unwrap_or("?").to_string();
            }
        });
        index = list.next_index(index);
    }
    println!("The {} -- {} {}!",
             list.get(list.move_index(index, 2)).unwrap(),
             list.get_first().unwrap(),
             list.get_last().unwrap());
}
