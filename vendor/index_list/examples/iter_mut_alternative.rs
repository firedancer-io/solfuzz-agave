/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use index_list::IndexList;

fn main() {
    let mut items =
        "ONE TWO THREE".split(' ').map(String::from).collect();
    let mut list: IndexList<String> = IndexList::from(&mut items);
    let mut index = list.first_index();
    while index.is_some() {
        let elem = list.get_mut(index).unwrap();
        *elem = elem.to_string().to_lowercase();
        index = list.next_index(index);
    }
    for item in &list {
        println!("{}", item);
    }
}
