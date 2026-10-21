//! Selecting several items in the list, like Finder or Mail.
//!
//! Pure function: the current selection, the displayed order and a gesture
//! give the new selection. Nothing here depends on the UI, hence the
//! tests below (the Swift app has no test target).
//!
//! - click: this item alone; it becomes the anchor;
//! - ⌘-click: adds or removes the item (never the last one); it becomes
//!   the anchor;
//! - ⇧-click: from the anchor to the item, in displayed order (replaces the
//!   selection, the anchor does not move);
//! - ↑/↓: neighbouring item alone; ⇧↑/⇧↓: extends (or shrinks) the range
//!   from the anchor;
//! - ⌘A: everything displayed; Esc: the active item alone.
//!
//! Linear cost in the number of rows, whatever the gesture: nothing
//! quadratic on each keystroke, even over thousands of items.

use std::collections::{HashMap, HashSet};

/// The selection: the items, in displayed order; the range anchor
/// (⇧); the active item, shown in the detail column.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListSelection {
    pub selected: Vec<String>,
    pub anchor: Option<String>,
    pub focus: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gesture {
    Click(String),
    /// ⌘-click.
    Toggle(String),
    /// ⇧-click.
    Extend(String),
    /// Arrows: `offset` rows down (negative: up); `extend`
    /// with ⇧.
    Step {
        offset: i32,
        extend: bool,
    },
    /// ⌘A.
    SelectAll,
    /// Esc: the active item alone.
    Collapse,
}

impl ListSelection {
    fn single(id: &str) -> Self {
        Self {
            selected: vec![id.to_owned()],
            anchor: Some(id.to_owned()),
            focus: Some(id.to_owned()),
        }
    }
}

/// The selection after `gesture`, over the items displayed in `order`.
/// Selected items that are no longer displayed are dropped.
#[must_use]
pub fn apply(current: &ListSelection, order: &[String], gesture: &Gesture) -> ListSelection {
    if order.is_empty() {
        return ListSelection::default();
    }
    let index: HashMap<&str, usize> = order
        .iter()
        .enumerate()
        .map(|(i, id)| (id.as_str(), i))
        .collect();
    let position = |id: &Option<String>| id.as_deref().and_then(|id| index.get(id).copied());
    let range = |from: usize, to: usize, anchor: usize| ListSelection {
        selected: order[from.min(to)..=from.max(to)].to_vec(),
        anchor: Some(order[anchor].clone()),
        focus: Some(order[to].clone()),
    };
    match gesture {
        Gesture::Click(id) => {
            if index.contains_key(id.as_str()) {
                ListSelection::single(id)
            } else {
                current.clone()
            }
        }
        Gesture::Toggle(id) => {
            let Some(&at) = index.get(id.as_str()) else {
                return current.clone();
            };
            let mut chosen: HashSet<usize> = current
                .selected
                .iter()
                .filter_map(|s| index.get(s.as_str()).copied())
                .collect();
            if chosen.contains(&at) {
                if chosen.len() == 1 {
                    return ListSelection::single(id);
                }
                chosen.remove(&at);
            } else {
                chosen.insert(at);
            }
            let mut positions: Vec<usize> = chosen.into_iter().collect();
            positions.sort_unstable();
            // Added: it becomes active. Removed: the active one stays,
            // otherwise the next one (or the last).
            let focus = if positions.binary_search(&at).is_ok() {
                at
            } else {
                position(&current.focus)
                    .filter(|f| positions.binary_search(f).is_ok())
                    .or_else(|| positions.iter().copied().find(|&p| p > at))
                    .unwrap_or(positions[positions.len() - 1])
            };
            ListSelection {
                selected: positions.into_iter().map(|p| order[p].clone()).collect(),
                anchor: Some(id.clone()),
                focus: Some(order[focus].clone()),
            }
        }
        Gesture::Extend(id) => {
            let Some(&to) = index.get(id.as_str()) else {
                return current.clone();
            };
            let anchor = position(&current.anchor)
                .or_else(|| position(&current.focus))
                .unwrap_or(to);
            range(anchor, to, anchor)
        }
        Gesture::Step { offset, extend } => {
            let last = order.len() - 1;
            let to = match position(&current.focus) {
                Some(focus) => focus.saturating_add_signed(*offset as isize).min(last),
                None => 0,
            };
            match position(&current.anchor) {
                Some(anchor) if *extend && position(&current.focus).is_some() => {
                    range(anchor, to, anchor)
                }
                _ => ListSelection::single(&order[to]),
            }
        }
        Gesture::SelectAll => {
            let focus = position(&current.focus).unwrap_or(0);
            ListSelection {
                selected: order.to_vec(),
                anchor: Some(order[position(&current.anchor).unwrap_or(focus)].clone()),
                focus: Some(order[focus].clone()),
            }
        }
        Gesture::Collapse => match position(&current.focus) {
            Some(focus) => ListSelection::single(&order[focus]),
            None => current.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order() -> Vec<String> {
        ["a", "b", "c", "d", "e", "f"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }

    fn sel(selected: &[&str], anchor: &str, focus: &str) -> ListSelection {
        ListSelection {
            selected: selected.iter().map(|s| (*s).to_owned()).collect(),
            anchor: Some(anchor.to_owned()),
            focus: Some(focus.to_owned()),
        }
    }

    #[allow(clippy::needless_pass_by_value)] // more readable in tests
    fn run(current: &ListSelection, gesture: Gesture) -> ListSelection {
        apply(current, &order(), &gesture)
    }

    #[test]
    fn click_selects_one_and_sets_the_anchor() {
        let s = run(&sel(&["a", "b"], "a", "b"), Gesture::Click("d".into()));
        assert_eq!(s, sel(&["d"], "d", "d"));
        // An item no longer displayed: nothing changes.
        let s2 = run(&s, Gesture::Click("z".into()));
        assert_eq!(s2, s);
    }

    #[test]
    fn command_click_toggles_in_display_order() {
        let s = run(&sel(&["d"], "d", "d"), Gesture::Toggle("b".into()));
        assert_eq!(s, sel(&["b", "d"], "b", "b"));
        let s = run(&s, Gesture::Toggle("f".into()));
        assert_eq!(s, sel(&["b", "d", "f"], "f", "f"));
        // Removing the active one: the next becomes active.
        let s = run(&s, Gesture::Toggle("d".into()));
        assert_eq!(s, sel(&["b", "f"], "d", "f"));
        // Removing another: the active one stays.
        let s = run(&s, Gesture::Toggle("b".into()));
        assert_eq!(s, sel(&["f"], "b", "f"));
        // Never empty.
        let s = run(&s, Gesture::Toggle("f".into()));
        assert_eq!(s, sel(&["f"], "f", "f"));
    }

    #[test]
    fn shift_click_selects_the_range_from_the_anchor() {
        let s = run(&sel(&["b"], "b", "b"), Gesture::Extend("e".into()));
        assert_eq!(s, sel(&["b", "c", "d", "e"], "b", "e"));
        // Upwards, from the same anchor: the range replaces.
        let s = run(&s, Gesture::Extend("a".into()));
        assert_eq!(s, sel(&["a", "b"], "b", "a"));
        // After a ⌘-click, the anchor is the clicked item.
        let s = run(&s, Gesture::Toggle("e".into()));
        let s = run(&s, Gesture::Extend("f".into()));
        assert_eq!(s, sel(&["e", "f"], "e", "f"));
        // No selection: the item alone.
        let s = run(&ListSelection::default(), Gesture::Extend("c".into()));
        assert_eq!(s, sel(&["c"], "c", "c"));
    }

    #[test]
    fn shift_arrows_extend_then_shrink_back_towards_the_anchor() {
        let start = sel(&["c"], "c", "c");
        let s = run(
            &start,
            Gesture::Step {
                offset: 1,
                extend: true,
            },
        );
        let s = run(
            &s,
            Gesture::Step {
                offset: 1,
                extend: true,
            },
        );
        assert_eq!(s, sel(&["c", "d", "e"], "c", "e"));
        let s = run(
            &s,
            Gesture::Step {
                offset: -1,
                extend: true,
            },
        );
        assert_eq!(s, sel(&["c", "d"], "c", "d"));
        let s = run(
            &s,
            Gesture::Step {
                offset: -3,
                extend: true,
            },
        );
        assert_eq!(s, sel(&["a", "b", "c"], "c", "a"));
        // Clamped at the ends.
        let s = run(
            &s,
            Gesture::Step {
                offset: -1,
                extend: true,
            },
        );
        assert_eq!(s, sel(&["a", "b", "c"], "c", "a"));
        // Without ⇧: the neighbouring item alone.
        let s = run(
            &s,
            Gesture::Step {
                offset: 1,
                extend: false,
            },
        );
        assert_eq!(s, sel(&["b"], "b", "b"));
        let s = run(
            &ListSelection::default(),
            Gesture::Step {
                offset: -1,
                extend: false,
            },
        );
        assert_eq!(s, sel(&["a"], "a", "a"));
    }

    #[test]
    fn select_all_then_escape() {
        let s = run(&sel(&["c"], "c", "c"), Gesture::SelectAll);
        assert_eq!(s.selected, order());
        assert_eq!(s.focus.as_deref(), Some("c"));
        let s = run(&s, Gesture::Collapse);
        assert_eq!(s, sel(&["c"], "c", "c"));
    }

    #[test]
    fn hidden_items_are_dropped_and_an_empty_list_clears() {
        // The search changed: "z" is no longer displayed.
        let s = run(&sel(&["z", "b"], "z", "z"), Gesture::Toggle("d".into()));
        assert_eq!(s, sel(&["b", "d"], "d", "d"));
        let s = run(&sel(&["z"], "z", "z"), Gesture::Extend("b".into()));
        assert_eq!(s, sel(&["b"], "b", "b"));
        assert_eq!(
            apply(&sel(&["a"], "a", "a"), &[], &Gesture::SelectAll),
            ListSelection::default()
        );
    }

    #[test]
    fn large_lists_stay_linear() {
        let order: Vec<String> = (0..10_000).map(|i| format!("id-{i}")).collect();
        let mut s = ListSelection::single("id-5000");
        let start = std::time::Instant::now();
        for _ in 0..200 {
            s = apply(
                &s,
                &order,
                &Gesture::Step {
                    offset: 1,
                    extend: true,
                },
            );
        }
        assert_eq!(s.selected.len(), 201);
        let s = apply(&s, &order, &Gesture::SelectAll);
        assert_eq!(s.selected.len(), 10_000);
        // Wide margin: a few milliseconds in debug.
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }
}
