use clap::Parser;
use colored::*;
use regex::Regex;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;


#[derive(Parser)]
#[command(name = "code-analyze")]
#[command(version = "1.0")]
#[command(about = "Static analyzer of code", long_about = None)]
struct Cli {
    path: String,

    #[arg(short, long)]
    errors_only: bool,

    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    #[arg(short, long)]
    ignore: Vec<String>
}


#[derive(clap::ValueEnum, Clone, Debug)]
enum OutputFormat {
    Text,
    Compact
}

#[derive(Debug, Clone)]
struct AnalysisResult {
    file: String,
    line: usize,
    message: String,
    severity: Severity,
    rule_name: String,
    code_snippet: String
}

#[derive(Debug, Clone)]
enum Severity {
    Error,
    Warning,
    Info,
}


impl Severity {
    fn to_colored_string(&self) -> ColoredString {
        match self {
            Severity::Error => "ERROR".red(),
            Severity::Info => "INFO".green(),
            Severity::Warning => "WARNING".yellow(),
        }
    }
}

#[derive(Debug)]
struct TextRule {
    name: String,
    pattern: Regex,
    message: String,
    severity: Severity,
    languages: Vec<String>,
}


impl TextRule {
    fn new(
        name: &str, 
        pattern: &str, 
        message: &str, 
        severity: Severity,
        languge: Vec<&str>
    ) -> Self {
        Self { 
            name: name.to_string(), 
            pattern: Regex::new(pattern).unwrap(), 
            message: message.to_string(), 
            severity, 
            languages: languge.iter().map(|s| s.to_string()).collect(), 
        }
    }
}



fn main() {
    let cli  = Cli::parse();
    if !Path::new(&cli.path).exists() {
        eprintln!("{}: путь '{}' не существует", "Ошибка".red(), cli.path);
        std::process::exit(1);
    }

    let results: Vec<AnalysisResult> = analyze_path(&cli.path, &cli.ignore);
    let filtered_results: Vec<AnalysisResult> = if cli.errors_only {
        results.into_iter()
            .filter(|r| matches!(r.severity, Severity::Error))
            .collect()
    } else {
        results
    };
    
    print_results(&filtered_results, &cli.format);


}


fn get_text_rules() -> Vec<TextRule> {
    vec![
        // Rust правила
        TextRule::new(
            "rust-unsafe-block",
            r"unsafe\s*\{",
            "Найден unsafe блок",
            Severity::Warning,
            vec!["rust"]
        ),
        TextRule::new(
            "rust-unwrap",
            r"\.unwrap\(\)",
            "Использование unwrap() может вызвать панику",
            Severity::Warning,
            vec!["rust"]
        ),
        TextRule::new(
            "rust-expect",
            r"\.expect\([^)]*\)",
            "Использование expect() может вызвать панику",
            Severity::Warning,
            vec!["rust"]
        ),
        TextRule::new(
            "rust-todo",
            r"//\s*TODO:?\s*.+",
            "Найден TODO комментарий",
            Severity::Info,
            vec!["rust"]
        ),
        TextRule::new(
            "rust-fixme", 
            r"//\s*FIXME:?\s*.+",
            "Найден FIXME комментарий",
            Severity::Info,
            vec!["rust"]
        ),
        
        // C правила
        TextRule::new(
            "c-unsafe-function",
            r"\b(gets|strcpy|sprintf)\s*\(",
            "Использование небезопасной функции",
            Severity::Error,
            vec!["c", "cpp"]
        ),
        TextRule::new(
            "c-malloc-without-free",
            r"malloc\s*\(",
            "malloc без проверки на free",
            Severity::Warning,
            vec!["c", "cpp"]
        ),
        TextRule::new(
            "c-printf-format",
            r"printf\s*\(",
            "Использование printf вместо fprintf/std::cout",
            Severity::Info,
            vec!["c", "cpp"]
        ),
        
        // Общие правила
        TextRule::new(
            "long-line",
            r"^.{100,}$",
            "Строка длиннее 100 символов",
            Severity::Warning,
            vec!["rust", "c", "cpp"]
        ),
         TextRule::new(
            "magic-number",
            r"(?x)                # Включение расширенного режима для комментариев
            \b                    # Граница слова
            (                     # Группа чисел
              0\b |              # 0 как отдельное число (но не в 0.5 или 0x)
              -1\b |             # -1 как отдельное число
              1\b |              # 1 как отдельное число (но не в 1.0 или 1e10)
              (?:                # Неcapturing группа для популярных магических чисел
                10|100|1000|     # Десятичные степени
                255|256|1024|    # Байтовые/компьютерные числа
                60|3600|24|7|    # Время (секунды, часы, дни, недели)
                8080|3000|3306   # Порт numbers
              )\b
            )
            (?!\.\d)             # Не после точки (исключает float)
            (?!\()               # Не перед скобкой (исключает вызовы функций)
            (?!\w)               # Не перед буквой (исключает идентификаторы)
            ",
            "Возможно магическое число - рассмотрите использование именованной константы",
            Severity::Info,
            vec!["rust", "c", "cpp"]
        ),
    ]
}



fn analyze_file(path: &Path, rules: &[TextRule]) -> Vec<AnalysisResult> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let extension = path.extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_lowercase();

    let mut results = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Пропускаем строки, которые являются комментариями
        if is_comment_line(line, &extension) {
            continue;
        }

        for rule in rules {
            if rule.languages.iter().any(|lang| matches_language(&extension, lang)) {
                if rule.pattern.is_match(line) && !is_false_positive(line, &rule.name) {
                    results.push(AnalysisResult {
                        file: path.display().to_string(),
                        line: line_num + 1,
                        message: rule.message.clone(),
                        severity: rule.severity.clone(),
                        rule_name: rule.name.clone(),
                        code_snippet: line.to_string(),
                    });
                }
            }
        }
    }

    results
}

// Проверяет, является ли строка комментарием
fn is_comment_line(line: &str, extension: &str) -> bool {
    match extension {
        "rs" => line.starts_with("//") || line.starts_with("/*") || line.starts_with("*"),
        "c" | "cpp" | "h" | "hpp" => line.starts_with("//") || line.starts_with("/*") || line.starts_with("*"),
        _ => false,
    }
}

// Проверяет ложные срабатывания для конкретных случаев
fn is_false_positive(line: &str, rule_name: &str) -> bool {
    if rule_name == "magic-number" {
        // Игнорируем числа в массивах инициализации
        if line.contains('[') && line.contains(']') {
            return true;
        }
        
        // Игнорируем версии в строках (v1.0.0)
        if line.contains("version") || line.contains("v1.") || line.contains("v0.") {
            return true;
        }
        
        // Игнорируем IP-адреса
        let ip_regex = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
        if ip_regex.is_match(line) {
            return true;
        }
    }
    false
}

fn analyze_path(path: &str, ignore_patterns: &[String]) -> Vec<AnalysisResult> {
    let mut results = Vec::new();
    let rules = get_text_rules();

    for entry in WalkDir::new(path) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if entry.file_type().is_file() {
            let path = entry.path();
            
            // Проверка игнорируемых паттернов
            if should_ignore(path, ignore_patterns) {
                continue;
            }
            
            let file_results = analyze_file(path, &rules);
            results.extend(file_results);
        }
    }

    results
}

fn matches_language(extension: &str, language: &str) -> bool {
    match language {
        "rust" => extension == "rs",
        "c" => extension == "c",
        "cpp" => extension == "cpp" || extension == "cxx" || extension == "cc" || extension == "hpp",
        _ => false,
    }
}

fn print_results(results: &[AnalysisResult], format: &OutputFormat) {
    match format {
        OutputFormat::Text => print_text_results(results),
        OutputFormat::Compact => print_compact_results(results),
    }
}

fn print_text_results(results: &[AnalysisResult]) {
    if results.is_empty() {
        println!("{}", "✓ Проблем не найдено".green());
        return;
    }

    println!("Результаты анализа:");
    println!("==================\n");

    for result in results {
        let severity_str = result.severity.to_colored_string();
        println!("{}: {}:{}", severity_str, result.file, result.line);
        println!("  Правило: {}", result.rule_name);
        println!("  Сообщение: {}", result.message);
        println!("  Код: {}", result.code_snippet.dimmed());
        println!();
    }

    let error_count = results.iter().filter(|r| matches!(r.severity, Severity::Error)).count();
    let warning_count = results.iter().filter(|r| matches!(r.severity, Severity::Warning)).count();
    let info_count = results.iter().filter(|r| matches!(r.severity, Severity::Info)).count();
    
    println!("Статистика:");
    println!("  Ошибки: {}", error_count.to_string().red());
    println!("  Предупреждения: {}", warning_count.to_string().yellow());
    println!("  Заметки: {}", info_count.to_string().blue());
    println!("  Всего: {}", results.len());
}


fn print_compact_results(results: &[AnalysisResult]) {
    for result in results {
        let severity_char = match result.severity {
            Severity::Error => "E",
            Severity::Warning => "W",
            Severity::Info => "I",
        };
        println!("{}:{}:{}: {} - {}", result.file, result.line, severity_char, result.rule_name, result.message);
    }
}

fn should_ignore(path: &Path, ignore_patterns: &[String]) -> bool {
    let path_str = path.to_string_lossy();
    
    // Автоматически игнорируем системные папки
    if path_str.contains("/target/") || 
       path_str.contains("/.git/") || 
       path_str.contains("/node_modules/") ||
       path_str.contains("/build/") {
        return true;
    }
    
    // Проверяем пользовательские паттерны
    for pattern in ignore_patterns {
        if path_str.contains(pattern) {
            return true;
        }
    }
    
    false
}
