/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use index_list::{IndexList, ListIndex};
use std::mem::size_of;
use std::collections::HashSet;
use rand::{Rng, seq::SliceRandom};

fn debug_print_indexes(list: &IndexList<u64>) {
    let mut index = list.first_index();
    let mut last = ListIndex::from(None);
    print!("[ ");
    while index.is_some() {
        if last.is_some() {
            print!(" >< ");
        }
        print!("{}", index);
        debug_assert_eq!(list.prev_index(index), last);
        last = index;
        index = list.next_index(index);
    }
    println!(" ]");
}
fn get_raw_index(index: &ListIndex) -> u32 {
    index.to_string().parse::<u32>().unwrap_or(0)
}

#[test]
fn test_instantiate() {
    let mut list = IndexList::<u64>::new();
    let null = ListIndex::from(None);
    assert_eq!(size_of::<ListIndex>(), 4);
    assert_eq!(list.len(), 0);
    assert_eq!(list.capacity(), 0);
    assert_eq!(list.is_index_used(null), false);
    assert_eq!(list.first_index(), null);
    assert_eq!(list.last_index(), null);
    assert_eq!(list.next_index(null), null);
    assert_eq!(list.prev_index(null), null);
    assert_eq!(list.move_index(null, 0), null);
    assert_eq!(list.get(null), None);
    assert_eq!(list.get_first(), None);
    assert_eq!(list.get_last(), None);
    assert_eq!(list.get_mut(null), None);
    assert_eq!(list.get_mut_first(), None);
    assert_eq!(list.get_mut_last(), None);
    assert_eq!(list.peek_next(null), None);
    assert_eq!(list.peek_prev(null), None);
    assert_eq!(list.remove_first(), None);
    assert_eq!(list.remove_last(), None);
    assert_eq!(list.remove(null), None);
    assert_eq!(list.index_of(0), null);
    assert_eq!(list.contains(0), false);
    assert_eq!(list.to_vec(), Vec::<&u64>::new());
    let mut empty_list = IndexList::new();
    list.append(&mut empty_list);
    list.prepend(&mut empty_list);
    list.split(null);
    list.trim_safe();
    list.trim_swap();
}
#[test]
fn basic_insert_remove() {
    let mut list = IndexList::<u64>::new();
    let count = 9;
    (0..count).for_each(|i| {
        let ndx = list.insert_first(i);
        assert_eq!(list.is_index_used(ndx), true);
    });
    println!("{}", list);
    assert_eq!(list.capacity(), count as usize);
    assert_eq!(list.len(), count as usize);
    list.trim_swap();
    (0..count).rev().for_each(|i| {
        assert_eq!(list.remove_first(), Some(i));
        assert_eq!(list.is_index_used(ListIndex::from(i as usize)), false);
        assert_eq!(list.len(), i as usize);
    });
    assert_eq!(list.remove_first(), None);
    assert_eq!(list.remove_last(), None);
    assert_eq!(list.capacity(), count as usize);
    list.trim_safe();
    assert_eq!(list.capacity(), 0);
}
#[test]
fn test_while_get_mut() {
    let mut strings = "A B C".split_whitespace().map(String::from).collect();
    let mut list: IndexList<String> = IndexList::from(&mut strings);
    let mut index = list.first_index();
    while index.is_some() {
        let elem = list.get_mut(index).unwrap();
        *elem = elem.to_string().to_lowercase();
        index = list.next_index(index);
    }
    assert_eq!(list.to_string(), "[a >< b >< c]");
}
#[test]
fn test_append() {
    let mut list = IndexList::from(&mut vec!["A", "B", "C"]);
    let mut other = IndexList::from(&mut vec!["D", "E", "F"]);
    list.append(&mut other);
    assert_eq!(list.len(), 6);
    assert_eq!(list.capacity(), 6);
    let index = list.move_index(list.first_index(), 3);
    assert_eq!(list.get(index), Some(&"D"));
    list.get_mut(index).map(|chr| {
        *chr = "G";
    });
    assert_eq!(list.get(index), Some(&"G"));
    let parts: Vec<&str> = list.iter().map(|e| e.as_ref()).collect();
    assert_eq!(parts.join(", "), "A, B, C, G, E, F");
    other = list.split(index);
    assert_eq!(list.to_string(), "[A >< B >< C]");
    assert_eq!(other.to_string(), "[G >< E >< F]");
}
#[test]
fn test_trim_swap() {
    let mut rng = rand::thread_rng();
    let mut list = IndexList::<u64>::new();
    for round in 0..16 {
        debug_print_indexes(&list);
        (0..16).for_each(|i| {
            let num = 16 * round + i;
            let ndx = list.insert_last(num);
            assert_eq!(list.get(ndx), Some(&num));
        });
        debug_print_indexes(&list);
        let mut indexes: Vec<usize> = (0..list.capacity()).collect();
        indexes.shuffle(&mut rng);
        (0..8).for_each(|_| {
            list.remove(ListIndex::from(indexes.pop()));
        });
        debug_print_indexes(&list);
        list.trim_swap();
        assert_eq!(list.capacity(), 8 + 8 * round as usize);
        assert_eq!(list.len(), list.capacity());
    }
}
#[test]
fn test_single_element() {
    let mut list = IndexList::<u64>::new();
    for num in 0..8 {
        match num & 1 {
            0 => list.insert_first(num),
            _ => list.insert_last(num),
        };
        match num & 2 {
            0 => assert_eq!(list.get_first(), Some(&num)),
            _ => assert_eq!(list.get_last(), Some(&num)),
        }
        let val = match num & 4 {
            0 => list.remove_first(),
            _ => list.remove_last(),
        };
        assert_eq!(val, Some(num));
    }
    assert_eq!(list.is_empty(), true);
    assert_eq!(list.capacity(), 1);
    assert_eq!(list.len(), 0);
}
#[test]
fn test_remove_element_twice() {
    let mut list = IndexList::<u64>::new();
    let index = list.insert_first(0);
    let removed1 = list.remove(index);
    assert_eq!(removed1, Some(0));
    let removed2 = list.remove(index);
    assert_eq!(removed2, None);
    assert_eq!(list.len(), 0);
}
#[test]
fn insert_remove_variants() {
    let count = 256;
    let mut rng = rand::thread_rng();
    let mut list = IndexList::<u64>::with_capacity(count);
    let mut numbers: HashSet<u64> = HashSet::with_capacity(count);
    let mut indexes: Vec<u32> = Vec::with_capacity(count);
    for _ in 0..8 {
        for c in 0..count {
            let num = c as u64;
            numbers.insert(num);
            print!("IndexList#{}: insert ", num);
            match c & 3 {
                0 => {
                    let ndx = list.insert_first(num);
                    println!("index {} first", ndx);
                    indexes.push(get_raw_index(&ndx));
                },
                1 => {
                    let that = ListIndex::from(indexes[rng.gen_range(0..c)] - 1);
                    print!("before {} ", that);
                    let ndx = list.insert_before(that, num);
                    println!("index {}", ndx);
                    indexes.push(get_raw_index(&ndx));
                },
                2 => {
                    let that = ListIndex::from(indexes[rng.gen_range(0..c)] - 1);
                    print!("after {} ", that);
                    let ndx = list.insert_after(that, num);
                    println!("index {} ", ndx);
                    indexes.push(get_raw_index(&ndx));
                },
                _ => {
                    let ndx = list.insert_last(num);
                    println!("index {} last", ndx);
                    indexes.push(get_raw_index(&ndx));
                },
            }
            print!("IndexList: ");
            debug_print_indexes(&list);
        }
        assert_eq!(list.len(), count);
        for c in (1..=count).rev() {
            let ndx = ListIndex::from(
                indexes.swap_remove(rng.gen_range(0..c as usize)) - 1);
            println!("IndexList - remove {}", ndx);
            let num = list.remove(ndx).unwrap();
            //println!("IndexList: {}", list.to_debug_string());
            assert!(numbers.remove(&num));
        }
        assert_eq!(list.capacity(), count);
        assert_eq!(list.len(), 0);
        assert!(numbers.is_empty());
        assert!(indexes.is_empty());
        list.trim_safe();
        assert_eq!(list.capacity(), 0);
    }
}
