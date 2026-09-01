//! Default colors and file classes (FR-5.4, FR-5.1).
//!
//! These ship as compiled-in defaults; M9 moves them into the TOML config
//! (FR-10.1) with per-theme variants (FR-11.5). Keeping them in one module
//! makes that move mechanical.

use egui::Color32;
use rss_core::Tag;
use rss_filter::FileClass;

/// Base colors for the **Flat Colors** style (FR-5.4): one base color per
/// element kind, darkened by nesting depth via the level-contrast factor.
#[derive(Clone)]
pub struct FlatColors {
    pub folder: Color32,
    pub file: Color32,
    pub free_space: Color32,
    pub unknown_space: Color32,
}

/// A file class bundled with its treemap color for the **File Classes**
/// style (FR-5.4); the same class table expands `:class:` filter conditions
/// (FR-4.8).
#[derive(Clone)]
pub struct ClassStyle {
    pub class: FileClass,
    pub color: Color32,
}

/// Default file classes; first match wins when coloring (FR-5.4).
pub fn file_class_styles() -> Vec<ClassStyle> {
    let mut styles = Vec::new();
    let mut add = |name: &str, extensions: &[&str], color: Color32| {
        styles.push(ClassStyle {
            class: FileClass::new(name, extensions.iter().copied()),
            color,
        });
    };
    add(
        "Audio/Music",
        &["mp3", "wav", "flac", "ogg", "aac", "m4a", "wma"],
        Color32::from_rgb(0xB0, 0x7A, 0xA1),
    );
    add(
        "Images",
        &["jpg", "jpeg", "png", "gif", "bmp", "tiff", "webp", "ico"],
        Color32::from_rgb(0x59, 0xA1, 0x4F),
    );
    add(
        "Video",
        &["mp4", "mkv", "avi", "mov", "wmv", "webm", "m4v"],
        Color32::from_rgb(0xE1, 0x57, 0x59),
    );
    add(
        "Archives",
        &["zip", "rar", "7z", "tar", "gz", "bz2", "xz"],
        Color32::from_rgb(0xF2, 0x8E, 0x2B),
    );
    add(
        "Documents",
        &[
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md",
        ],
        Color32::from_rgb(0x4E, 0x79, 0xA7),
    );
    add(
        "Executables",
        &["exe", "dll", "sys", "msi", "bat", "ps1", "com"],
        Color32::from_rgb(0x9C, 0x75, 0x5F),
    );
    add(
        "Code",
        &["rs", "c", "cpp", "h", "hpp", "py", "js", "ts", "java", "go"],
        Color32::from_rgb(0x76, 0xB7, 0xB2),
    );
    styles
}

/// The four tag colors (FR-5.1).
pub fn tag_color(tag: Tag) -> Color32 {
    match tag {
        Tag::Red => Color32::from_rgb(0xE2, 0x4A, 0x33),
        Tag::Yellow => Color32::from_rgb(0xED, 0xC9, 0x48),
        Tag::Green => Color32::from_rgb(0x4F, 0xA9, 0x5B),
        Tag::Blue => Color32::from_rgb(0x4A, 0x90, 0xD9),
    }
}

/// A full per-theme palette (FR-11.5): flat colors, tag colors, and class
/// colors all have a dark and a light variant. M9 persists user
/// customizations per theme in the config file.
#[derive(Clone)]
pub struct Palette {
    pub flat: FlatColors,
    /// Tag border colors in red/yellow/green/blue order.
    pub tags: [Color32; 4],
    pub classes: Vec<ClassStyle>,
    /// Level-contrast factor (FR-5.4): < 1 darkens by depth, > 1 lightens.
    /// FR-11.6: the dark theme lightens by depth so nested folders stay
    /// legible against the dark background; the light theme darkens.
    pub level_contrast: f32,
}

fn classes_with(colors: [Color32; 7]) -> Vec<ClassStyle> {
    file_class_styles()
        .into_iter()
        .zip(colors)
        .map(|(mut style, color)| {
            style.color = color;
            style
        })
        .collect()
}

/// The default palette for a theme (FR-11.5/FR-11.6). Both variants are
/// WCAG-AA-checked in the unit tests (FR-11.7).
pub fn palette(dark: bool) -> Palette {
    if dark {
        Palette {
            flat: FlatColors {
                folder: Color32::from_rgb(0x8A, 0x9A, 0xB0),
                file: Color32::from_rgb(0x4E, 0x79, 0xA7),
                free_space: Color32::from_rgb(0x3A, 0x3A, 0x3A),
                unknown_space: Color32::from_rgb(0x5A, 0x4A, 0x6A),
            },
            tags: [
                tag_color(Tag::Red),
                tag_color(Tag::Yellow),
                tag_color(Tag::Green),
                tag_color(Tag::Blue),
            ],
            classes: classes_with([
                Color32::from_rgb(0xB0, 0x7A, 0xA1),
                Color32::from_rgb(0x59, 0xA1, 0x4F),
                Color32::from_rgb(0xE1, 0x57, 0x59),
                Color32::from_rgb(0xF2, 0x8E, 0x2B),
                Color32::from_rgb(0x4E, 0x79, 0xA7),
                Color32::from_rgb(0x7A, 0x59, 0x44),
                Color32::from_rgb(0x5E, 0x8F, 0x8D),
            ]),
            level_contrast: 1.12, // lighten by depth (FR-11.6)
        }
    } else {
        // Light theme: deeper variants so cell text (near-black) keeps AA
        // contrast against them.
        Palette {
            flat: FlatColors {
                folder: Color32::from_rgb(0x5E, 0x6E, 0x84),
                file: Color32::from_rgb(0x33, 0x5E, 0x8C),
                free_space: Color32::from_rgb(0xC8, 0xC8, 0xC8),
                unknown_space: Color32::from_rgb(0x6B, 0x55, 0x80),
            },
            tags: [
                Color32::from_rgb(0xB8, 0x30, 0x1C),
                Color32::from_rgb(0x8F, 0x71, 0x0A),
                Color32::from_rgb(0x2F, 0x7A, 0x3B),
                Color32::from_rgb(0x2C, 0x66, 0xA8),
            ],
            classes: classes_with([
                Color32::from_rgb(0x7A, 0x4E, 0x6E),
                Color32::from_rgb(0x38, 0x6E, 0x31),
                Color32::from_rgb(0xA8, 0x32, 0x34),
                Color32::from_rgb(0xA8, 0x5E, 0x0A),
                Color32::from_rgb(0x33, 0x5E, 0x8C),
                Color32::from_rgb(0x6E, 0x50, 0x3C),
                Color32::from_rgb(0x47, 0x80, 0x7E),
            ]),
            level_contrast: 0.85, // darken by depth
        }
    }
}

/// WCAG 2.x relative luminance of a color (FR-11.7 checks).
pub fn relative_luminance(c: Color32) -> f32 {
    let f = |v: u8| {
        let c = f32::from(v) / 255.0;
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * f(c.r()) + 0.7152 * f(c.g()) + 0.0722 * f(c.b())
}

/// WCAG contrast ratio between two colors (1..21).
pub fn contrast_ratio(a: Color32, b: Color32) -> f32 {
    let (la, lb) = (relative_luminance(a), relative_luminance(b));
    let (hi, lo) = (la.max(lb), la.min(lb));
    (hi + 0.05) / (lo + 0.05)
}

/// Readable text color on top of `bg`: whichever of near-black / white has
/// the higher WCAG contrast (FR-11.7).
pub fn contrast_text(bg: Color32) -> Color32 {
    let black = Color32::from_rgb(0x1B, 0x1B, 0x1B);
    if contrast_ratio(Color32::WHITE, bg) >= contrast_ratio(black, bg) {
        Color32::WHITE
    } else {
        black
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-11.7: every shipped palette color must give cell text WCAG AA
    /// contrast (>= 4.5:1) with the [`contrast_text`] choice.
    #[test]
    fn default_palettes_meet_wcag_aa() {
        for dark in [true, false] {
            let palette = palette(dark);
            let colors: Vec<Color32> = [
                palette.flat.folder,
                palette.flat.file,
                palette.flat.free_space,
                palette.flat.unknown_space,
            ]
            .into_iter()
            .chain(palette.classes.iter().map(|c| c.color))
            .collect();
            for color in colors {
                let text = contrast_text(color);
                let ratio = contrast_ratio(text, color);
                assert!(
                    ratio >= 4.5,
                    "theme dark={dark}: text {text:?} on {color:?} has contrast {ratio:.2}"
                );
            }
        }
    }

    #[test]
    fn default_classes_have_unique_names_and_extensions() {
        let styles = file_class_styles();
        assert!(!styles.is_empty());
        let mut names: Vec<_> = styles.iter().map(|s| s.class.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), styles.len(), "duplicate class names");
        for style in &styles {
            assert!(!style.class.extensions.is_empty());
            for ext in &style.class.extensions {
                assert_eq!(*ext, ext.to_lowercase(), "extensions are normalized");
            }
        }
    }
}
