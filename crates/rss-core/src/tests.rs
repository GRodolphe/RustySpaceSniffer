use crate::*;

fn dir(name: &str) -> NodeParams {
    NodeParams::named(name, NodeKind::Directory)
}

fn file(name: &str, logical: u64, allocated: u64) -> NodeParams {
    NodeParams::named(name, NodeKind::File).sizes(logical, allocated)
}

#[test]
fn aggregates_propagate_to_ancestors() {
    let mut tree = Tree::with_root(dir("root"));
    let root = tree.root().unwrap();
    let sub = tree.add_child(root, dir("sub"));
    let f1 = tree.add_child(sub, file("a.bin", 100, 4096));
    let _f2 = tree.add_child(root, file("b.bin", 50, 4096));

    let root_node = tree.node(root);
    assert_eq!(root_node.agg_logical, 150);
    assert_eq!(root_node.agg_allocated, 8192);
    assert_eq!(root_node.agg_files, 2);
    assert_eq!(root_node.agg_dirs, 2); // root + sub

    tree.set_own_sizes(f1, 200, 8192, 0);
    assert_eq!(tree.node(root).agg_logical, 250);
    assert_eq!(tree.node(root).agg_allocated, 12288);
}

#[test]
fn remove_subtree_propagates_negative_deltas() {
    let mut tree = Tree::with_root(dir("root"));
    let root = tree.root().unwrap();
    let sub = tree.add_child(root, dir("sub"));
    tree.add_child(sub, file("a.bin", 100, 4096));
    tree.add_child(root, file("b.bin", 50, 4096));

    tree.remove_subtree(sub);
    let root_node = tree.node(root);
    assert_eq!(root_node.agg_logical, 50);
    assert_eq!(root_node.agg_allocated, 4096);
    assert_eq!(root_node.agg_files, 1);
    assert_eq!(root_node.agg_dirs, 1);
    assert_eq!(tree.children(root).count(), 1);
}

#[test]
fn children_and_paths() {
    let mut tree = Tree::with_root(dir("root"));
    let root = tree.root().unwrap();
    let sub = tree.add_child(root, dir("sub"));
    let f = tree.add_child(sub, file("a.txt", 1, 4096));

    let kids: Vec<NodeId> = tree.children(root).collect();
    assert_eq!(kids, vec![sub]);
    assert_eq!(tree.path_components(f), vec!["root", "sub", "a.txt"]);
}

#[test]
fn ads_counts_toward_allocated_aggregate() {
    let mut tree = Tree::with_root(dir("root"));
    let root = tree.root().unwrap();
    let mut params = file("hosted.txt", 10, 4096);
    params.ads_size = 2048;
    tree.add_child(root, params);
    assert_eq!(tree.node(root).agg_allocated, 4096 + 2048);
}

#[test]
fn free_slots_are_recycled() {
    let mut tree = Tree::with_root(dir("root"));
    let root = tree.root().unwrap();
    let sub = tree.add_child(root, dir("sub"));
    tree.add_child(sub, file("a.bin", 1, 1));
    let len_before = tree.len();
    tree.remove_subtree(sub);
    assert_eq!(tree.len(), len_before - 2);
    tree.add_child(root, dir("reused"));
    assert_eq!(tree.len(), len_before - 1);
}

#[test]
fn filetime_unix_roundtrip() {
    let ft = filetime_from_unix(1_700_000_000);
    assert_eq!(filetime_to_unix(ft), 1_700_000_000);
}
