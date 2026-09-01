//! Template engine tests (FR-8.1/FR-8.2/FR-8.3, SPEC.md §4.8): placeholder
//! substitution, commands, conditionals, sorting, the built-in "Grouped by
//! folder" configuration, typed errors with spans, and a garbage-feeding
//! smoke run of the fuzz entry point.

use rss_core::{filetime_from_unix, NodeId, NodeKind, NodeParams, Tree};
use rss_export::{
    builtin_templates, find_builtin_template, render_template, BlockSort, ExportError,
    ExportTemplate, SortField, TemplateContext, TemplateError,
};

const T0: i64 = 1_700_000_000; // 2023-11-14T22:13:20Z

/// ```text
/// root/                 dir,   modified T0
/// ├── docs/             dir,   modified T0+200
/// │   ├── b.txt         file   1_000 / 4_096, modified T0+300
/// │   └── a.txt         file   2_000 / 4_096, modified T0+400
/// └── big.bin           file   10_000 / 16_384, modified T0+100
/// ```
fn test_tree() -> (Tree, NodeId) {
    let mut tree = Tree::with_root(
        NodeParams::named("root", NodeKind::Directory).modified(filetime_from_unix(T0)),
    );
    let root = tree.root().unwrap();
    let docs = tree.add_child(
        root,
        NodeParams::named("docs", NodeKind::Directory).modified(filetime_from_unix(T0 + 200)),
    );
    tree.add_child(
        docs,
        NodeParams::named("b.txt", NodeKind::File)
            .sizes(1_000, 4_096)
            .modified(filetime_from_unix(T0 + 300)),
    );
    tree.add_child(
        docs,
        NodeParams::named("a.txt", NodeKind::File)
            .sizes(2_000, 4_096)
            .modified(filetime_from_unix(T0 + 400)),
    );
    tree.add_child(
        root,
        NodeParams::named("big.bin", NodeKind::File)
            .sizes(10_000, 16_384)
            .modified(filetime_from_unix(T0 + 100)),
    );
    (tree, root)
}

fn template(detail: &str) -> ExportTemplate {
    ExportTemplate {
        name: "test".to_string(),
        header: String::new(),
        detail: detail.to_string(),
        footer: String::new(),
        block_sort: BlockSort::None,
        sort: SortField::Name,
        descending: false,
    }
}

fn render(tpl: &ExportTemplate) -> String {
    let (tree, root) = test_tree();
    let ctx = TemplateContext {
        filter: None,
        now: filetime_from_unix(T0 + 3_600),
    };
    let mut out = Vec::new();
    render_template(&tree, root, tpl, &ctx, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// Render and strip the FR-8.1 prologue (three `#` lines).
fn render_body(tpl: &ExportTemplate) -> String {
    render(tpl).lines().skip(3).collect::<Vec<_>>().join("\n")
}

fn render_err(tpl: &ExportTemplate) -> TemplateError {
    let (tree, root) = test_tree();
    let ctx = TemplateContext::default();
    let err = render_template(&tree, root, tpl, &ctx, Vec::new()).unwrap_err();
    match err {
        ExportError::Template(t) => t,
        other => panic!("expected TemplateError, got {other:?}"),
    }
}

// ---- placeholders ----

#[test]
fn placeholder_values() {
    // Detail rendered per node in pre-order (BlockSort::None, name order:
    // big.bin, docs/a.txt, docs/b.txt — name sort: big.bin < docs).
    let out = render_body(&template(
        "<%file%>|<%fileext%>|<%sizebytes%>|<%disksizebytes%>|<%isfile%>|<%isfolder%>|<%iscontainer%>|<%nestinglevel%>{&br}",
    ));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "root||13000|24576|0|1|0|0");
    assert_eq!(lines[1], "big.bin|bin|10000|16384|1|0|0|1");
    assert_eq!(lines[2], "docs||3000|8192|0|1|0|1");
    assert_eq!(lines[3], "a.txt|txt|2000|4096|1|0|0|2");
    assert_eq!(lines[4], "b.txt|txt|1000|4096|1|0|0|2");
}

#[test]
fn placeholder_paths_and_dates() {
    let out = render_body(&template(
        "<%pathfile%> ;; <%path%> ;; <%filemodifydate%> ;; <%age%>{&br}",
    ));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[0], "root ;;  ;; 2023-11-14T22:13:20Z ;; 1h",
        "root has no parent path"
    );
    assert_eq!(
        lines[1],
        "root/big.bin ;; root ;; 2023-11-14T22:15:00Z ;; 58m"
    );
    assert_eq!(
        lines[4],
        "root/docs/b.txt ;; root/docs ;; 2023-11-14T22:18:20Z ;; 55m"
    );
}

#[test]
fn placeholder_human_sizes() {
    let out = render_body(&template("<%size%>/<%disksize%>{&br}"));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[1], "9.8 KB/16.0 KB"); // big.bin: 10_000 / 16_384
    assert_eq!(lines[3], "2.0 KB/4.0 KB"); // a.txt: 2_000 / 4_096
}

#[test]
fn placeholder_counters() {
    let out = render_body(&template(
        "<%counter%>,<%filecounter%>,<%foldercounter%>{&br}",
    ));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "1,0,1");
    assert_eq!(lines[1], "2,1,1");
    assert_eq!(lines[2], "3,1,2");
    assert_eq!(lines[3], "4,2,2");
    assert_eq!(lines[4], "5,3,2");
}

#[test]
fn literal_brace_escape_and_passthrough() {
    let out = render_body(&template("literal {{brace}} 100% ok{&br}"));
    for line in out.lines() {
        assert_eq!(line, "literal {brace}} 100% ok");
    }
}

// ---- commands ----

#[test]
fn commands_br_tab_nest() {
    let out = render_body(&template("[{nest}<%file%>]{&br}"));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "[root]");
    assert_eq!(lines[1], "[  big.bin]");
    assert_eq!(lines[3], "[    a.txt]");
}

#[test]
fn commands_leftpad_rightpad() {
    let out = render_body(&template("<{leftpad 6}<%file%>|{rightpad 6}<%file%>>{&br}"));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "<  root|root  >");
    assert_eq!(lines[1], "<big.bin|big.bin>");
}

#[test]
fn pad_allows_intervening_whitespace_only() {
    let out = render_body(&template("{leftpad 8}  <%file%>{&br}"));
    assert_eq!(out.lines().next().unwrap(), "      root");
    let err = render_err(&template("{leftpad 8}x<%file%>"));
    assert!(matches!(err, TemplateError::DanglingPad { .. }));
}

#[test]
fn dangling_pad_at_section_end() {
    let err = render_err(&template("<%file%>{leftpad 5}"));
    assert!(matches!(err, TemplateError::DanglingPad { .. }));
}

#[test]
fn invalid_command_args() {
    let err = render_err(&template("{leftpad}<%file%>"));
    assert!(matches!(err, TemplateError::InvalidCommandArg { .. }));
    let err = render_err(&template("{leftpad nope}<%file%>"));
    assert!(matches!(err, TemplateError::InvalidCommandArg { .. }));
    let err = render_err(&template("{leftpad 99999999}<%file%>"));
    assert!(matches!(err, TemplateError::InvalidCommandArg { .. }));
    let err = render_err(&template("{nest 999}<%file%>"));
    assert!(matches!(err, TemplateError::InvalidCommandArg { .. }));
}

// ---- conditionals ----

#[test]
fn conditional_if_else_endif() {
    let out = render_body(&template("{if isfolder}DIR{else}file{endif}:<%file%>{&br}"));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "DIR:root");
    assert_eq!(lines[1], "file:big.bin");
    assert_eq!(lines[2], "DIR:docs");
    assert_eq!(lines[3], "file:a.txt");
}

#[test]
fn conditional_negation_and_nesting() {
    let out = render_body(&template(
        "{if !isfolder}F{else}{if iscontainer}C{else}D{endif}{endif}{&br}",
    ));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "D");
    assert_eq!(lines[1], "F");
    assert_eq!(lines[2], "D");
}

#[test]
fn conditional_errors() {
    let err = render_err(&template("{if isfolder}never closed"));
    assert!(matches!(err, TemplateError::MissingEndif { .. }));

    let err = render_err(&template("{endif}"));
    assert!(matches!(
        err,
        TemplateError::UnmatchedConditional {
            command: "endif",
            ..
        }
    ));

    let err = render_err(&template("{else}"));
    assert!(matches!(
        err,
        TemplateError::UnmatchedConditional {
            command: "else",
            ..
        }
    ));

    let err = render_err(&template("{if size > 3}x{endif}"));
    assert!(matches!(err, TemplateError::InvalidCondition { .. }));

    // Nesting beyond the cap (32) is a typed error, not a stack overflow.
    // Balanced, so the deep nesting is actually reached for file nodes.
    let mut nested = String::new();
    for _ in 0..40 {
        nested.push_str("{if isfile}");
    }
    nested.push('x');
    for _ in 0..40 {
        nested.push_str("{endif}");
    }
    let err = render_err(&template(&nested));
    assert!(matches!(
        err,
        TemplateError::ConditionalNestingTooDeep { .. }
    ));
}

// ---- error spans ----

#[test]
fn unknown_placeholder_error_has_span() {
    let detail = "x <%bogus%> y";
    let err = render_err(&template(detail));
    match err {
        TemplateError::UnknownPlaceholder {
            name,
            section,
            span,
        } => {
            assert_eq!(name, "bogus");
            assert_eq!(section, "detail");
            assert_eq!(&detail[span], "<%bogus%>");
        }
        other => panic!("expected UnknownPlaceholder, got {other:?}"),
    }
}

#[test]
fn unterminated_placeholder_and_command() {
    let err = render_err(&template("abc <%file"));
    assert!(matches!(
        err,
        TemplateError::UnterminatedPlaceholder {
            section: "detail",
            ..
        }
    ));
    let err = render_err(&template("abc {&br"));
    assert!(matches!(
        err,
        TemplateError::UnterminatedCommand {
            section: "detail",
            ..
        }
    ));
}

#[test]
fn unknown_command_and_script_rejected() {
    let err = render_err(&template("{frobnicate}"));
    assert!(matches!(err, TemplateError::UnknownCommand { .. }));

    let err = render_err(&template("{script rm -rf /}"));
    assert!(matches!(err, TemplateError::UnsupportedCommand { .. }));
}

#[test]
fn header_section_errors_are_attributed() {
    let mut tpl = template("<%file%>");
    tpl.header = "<%oops%>".to_string();
    let err = render_err(&tpl);
    assert!(matches!(
        err,
        TemplateError::UnknownPlaceholder {
            section: "header",
            ..
        }
    ));
}

// ---- sorting ----

#[test]
fn block_sort_folders_first_then_files() {
    let mut tpl = template("<%file%>{&br}");
    tpl.block_sort = BlockSort::FoldersFirst;
    let out = render_body(&tpl);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines, ["root", "docs", "a.txt", "b.txt", "big.bin"]);
}

#[test]
fn block_sort_files_first_then_folders() {
    let mut tpl = template("<%file%>{&br}");
    tpl.block_sort = BlockSort::FilesFirst;
    let out = render_body(&tpl);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines, ["root", "big.bin", "docs", "a.txt", "b.txt"]);
}

#[test]
fn fine_sort_size_descending() {
    let mut tpl = template("<%file%>{&br}");
    tpl.sort = SortField::Size;
    tpl.descending = true;
    let out = render_body(&tpl);
    let lines: Vec<&str> = out.lines().collect();
    // Within docs: a.txt (2000) before b.txt (1000); big.bin largest overall.
    assert_eq!(lines, ["root", "big.bin", "docs", "a.txt", "b.txt"]);
}

// ---- built-in configurations and FR-8.1 header ----

#[test]
fn builtin_grouped_by_folder() {
    let builtins = builtin_templates();
    let grouped = find_builtin_template("Grouped by folder").expect("built-in exists (FR-8.3)");
    assert!(builtins.iter().any(|t| t.name == "Grouped by folder"));
    assert_eq!(grouped.name, "Grouped by folder");

    let out = render(&grouped);
    let expected = "\
# RustySpaceSniffer export (template: Grouped by folder)
# view: root
# filter: none
Grouped by folder report

     12.7 KB root
      2.9 KB   docs
      2.0 KB     a.txt
      1000 B     b.txt
      9.8 KB   big.bin

5 elements, 2 folders, 3 files
";
    assert_eq!(out, expected);
}

#[test]
fn header_states_view_and_filter() {
    // FR-8.1: the output header states the zoom and the active filter.
    let (tree, _root) = test_tree();
    let docs = tree
        .children(tree.root().unwrap())
        .find(|&c| &*tree.node(c).name == "docs")
        .unwrap();
    let ctx = TemplateContext {
        filter: Some("*.jpg;>1mb"),
        now: filetime_from_unix(T0),
    };
    let mut out = Vec::new();
    render_template(&tree, docs, &template("<%file%>{&br}"), &ctx, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "# RustySpaceSniffer export (template: test)");
    assert_eq!(lines[1], "# view: root/docs");
    assert_eq!(lines[2], "# filter: *.jpg;>1mb");
    // The zoom root itself is the first detail line.
    assert_eq!(lines[3], "docs");
}

#[test]
fn invalid_root_is_typed_error() {
    let (tree, _root) = test_tree();
    let err = render_template(
        &tree,
        999,
        &template("x"),
        &TemplateContext::default(),
        Vec::new(),
    )
    .unwrap_err();
    assert!(matches!(err, ExportError::InvalidRoot(999)));
}

#[test]
fn unicode_names_render() {
    let mut tree = Tree::with_root(NodeParams::named("ルート", NodeKind::Directory));
    let root = tree.root().unwrap();
    tree.add_child(
        root,
        NodeParams::named("ファイル 📁.txt", NodeKind::File).sizes(7, 4096),
    );
    let out = {
        let mut buf = Vec::new();
        render_template(
            &tree,
            root,
            &template("<%pathfile%>=<%sizebytes%>{&br}"),
            &TemplateContext::default(),
            &mut buf,
        )
        .unwrap();
        String::from_utf8(buf).unwrap()
    };
    let body: Vec<&str> = out.lines().skip(3).collect();
    assert_eq!(body[0], "ルート=7");
    assert_eq!(body[1], "ルート/ファイル 📁.txt=7");
}

// ---- fuzz-entry smoke test (same code as the cargo-fuzz target) ----

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn template_render_garbage_never_panics() {
    let mut rng = Rng(0xfeed_beef_cafe_0001);
    // Pure garbage.
    for _ in 0..2_000 {
        let len = (rng.next() % 400) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = rng.next() as u8;
        }
        rss_export::fuzzing::template_render(&buf);
    }
    // Garbage biased toward template metacharacters.
    let alphabet = b"<%{}>iftabnelsorp&!0123456789 \n";
    for _ in 0..5_000 {
        let len = (rng.next() % 200) as usize;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(alphabet[(rng.next() as usize) % alphabet.len()]);
        }
        rss_export::fuzzing::template_render(&buf);
    }
}
