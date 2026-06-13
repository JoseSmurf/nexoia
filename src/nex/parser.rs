use crate::quality::EvidenceStrength;
use std::error::Error;
use std::fmt;

use super::ast::{Action, Expr, Program, Stmt, Type};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

impl ParseError {
    fn new(line: usize, column: usize, message: impl Into<String>) -> Self {
        Self {
            line,
            column,
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}:{}: {}", self.line, self.column, self.message)
    }
}

impl Error for ParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Word(String),
    Int(i64),
    Str(String),
    Eq,
    Gte,
}

impl TokenKind {
    fn as_text(&self) -> String {
        match self {
            Self::Word(value) => value.clone(),
            Self::Int(value) => value.to_string(),
            Self::Str(value) => format!("{value:?}"),
            Self::Eq => "=".to_string(),
            Self::Gte => ">=".to_string(),
        }
    }
}

pub fn parse(source: &str) -> Result<Program, ParseError> {
    let mut statements = Vec::new();

    for (line_idx, raw_line) in source.lines().enumerate() {
        let line_no = line_idx + 1;
        let tokens = lex_line(raw_line, line_no)?;
        if tokens.is_empty() {
            continue;
        }
        statements.push(parse_statement(&tokens, line_no)?);
    }

    Ok(Program { statements })
}

fn lex_line(line: &str, line_no: usize) -> Result<Vec<Token>, ParseError> {
    let chars: Vec<char> = line.chars().collect();
    let mut tokens = Vec::new();
    let mut idx = 0;

    while idx < chars.len() {
        let ch = chars[idx];
        if ch.is_whitespace() {
            idx += 1;
            continue;
        }
        if ch == '#' {
            break;
        }

        let column = idx + 1;
        let token = match ch {
            '=' => {
                idx += 1;
                Token {
                    kind: TokenKind::Eq,
                    column,
                }
            }
            '>' if chars.get(idx + 1) == Some(&'=') => {
                idx += 2;
                Token {
                    kind: TokenKind::Gte,
                    column,
                }
            }
            '"' => {
                idx += 1;
                let mut value = String::new();
                let mut closed = false;

                while idx < chars.len() {
                    let current = chars[idx];
                    match current {
                        '"' => {
                            idx += 1;
                            closed = true;
                            break;
                        }
                        '\\' => {
                            idx += 1;
                            let escaped = chars.get(idx).ok_or_else(|| {
                                ParseError::new(line_no, column, "unterminated string literal")
                            })?;
                            let decoded = match escaped {
                                '"' => '"',
                                '\\' => '\\',
                                'n' => '\n',
                                't' => '\t',
                                other => *other,
                            };
                            value.push(decoded);
                            idx += 1;
                        }
                        other => {
                            value.push(other);
                            idx += 1;
                        }
                    }
                }

                if !closed {
                    return Err(ParseError::new(
                        line_no,
                        column,
                        "unterminated string literal",
                    ));
                }

                Token {
                    kind: TokenKind::Str(value),
                    column,
                }
            }
            '-' if chars.get(idx + 1).is_some_and(|next| next.is_ascii_digit()) => {
                let start = idx;
                idx += 1;
                while chars.get(idx).is_some_and(|next| next.is_ascii_digit()) {
                    idx += 1;
                }
                let text: String = chars[start..idx].iter().collect();
                let value = text.parse::<i64>().map_err(|err| {
                    ParseError::new(
                        line_no,
                        column,
                        format!("invalid integer literal '{text}': {err}"),
                    )
                })?;
                Token {
                    kind: TokenKind::Int(value),
                    column,
                }
            }
            other if other.is_ascii_digit() => {
                let start = idx;
                idx += 1;
                while chars.get(idx).is_some_and(|next| next.is_ascii_digit()) {
                    idx += 1;
                }
                let text: String = chars[start..idx].iter().collect();
                let value = text.parse::<i64>().map_err(|err| {
                    ParseError::new(
                        line_no,
                        column,
                        format!("invalid integer literal '{text}': {err}"),
                    )
                })?;
                Token {
                    kind: TokenKind::Int(value),
                    column,
                }
            }
            other => {
                let start = idx;
                idx += 1;
                while idx < chars.len() {
                    let next = chars[idx];
                    if next.is_whitespace()
                        || next == '#'
                        || next == '='
                        || next == '"'
                        || next == '>'
                    {
                        break;
                    }
                    idx += 1;
                }
                let text: String = chars[start..idx].iter().collect();
                if text.is_empty() {
                    return Err(ParseError::new(
                        line_no,
                        column,
                        format!("unexpected character '{other}'"),
                    ));
                }
                Token {
                    kind: TokenKind::Word(text),
                    column,
                }
            }
        };

        tokens.push(token);
    }

    Ok(tokens)
}

fn parse_statement(tokens: &[Token], line_no: usize) -> Result<Stmt, ParseError> {
    let first = tokens
        .first()
        .ok_or_else(|| ParseError::new(line_no, 1, "empty statement"))?;
    let keyword = word(first, line_no)?;

    match keyword.as_str() {
        "use" => parse_use(tokens, line_no),
        "let" => parse_let(tokens, line_no),
        "attest" => parse_attest(tokens, line_no),
        "assert" => parse_assert(tokens, line_no),
        "act" => parse_act(tokens, line_no),
        other => Err(ParseError::new(
            line_no,
            first.column,
            format!("unknown keyword '{other}'"),
        )),
    }
}

fn parse_use(tokens: &[Token], line_no: usize) -> Result<Stmt, ParseError> {
    let path_token = tokens.get(1).ok_or_else(|| {
        ParseError::new(
            line_no,
            tokens[0].column + 1,
            "expected import path after 'use'",
        )
    })?;
    let path = parse_import_path(path_token, line_no)?;
    ensure_end(tokens, 2, line_no)?;
    Ok(Stmt::Use { path })
}

fn parse_let(tokens: &[Token], line_no: usize) -> Result<Stmt, ParseError> {
    let id = expect_word(tokens, 1, line_no, "expected identifier after 'let'")?;
    expect_eq(tokens, 2, line_no, "expected '=' after identifier")?;
    let next = tokens.get(3).ok_or_else(|| {
        ParseError::new(
            line_no,
            tokens[2].column + 1,
            "expected expression after '='",
        )
    })?;

    match &next.kind {
        TokenKind::Word(value) if value == "node" => {
            let expr_token = tokens.get(4).ok_or_else(|| {
                ParseError::new(
                    line_no,
                    next.column,
                    "missing value expression after 'node'",
                )
            })?;
            let value = parse_expr(expr_token)?;
            let strength_token = tokens.get(5).ok_or_else(|| {
                ParseError::new(
                    line_no,
                    expr_token.column,
                    "missing strength after node value",
                )
            })?;
            let strength = parse_strength(strength_token, line_no)?;
            ensure_end(tokens, 6, line_no)?;
            Ok(Stmt::Node {
                id,
                value,
                strength,
            })
        }
        TokenKind::Word(left) => {
            let derive_token = tokens.get(4).ok_or_else(|| {
                ParseError::new(
                    line_no,
                    next.column,
                    "expected 'derive' after left identifier",
                )
            })?;
            if word(derive_token, line_no)? != "derive" {
                return Err(ParseError::new(
                    line_no,
                    derive_token.column,
                    "expected 'derive' after left identifier",
                ));
            }
            let right = expect_word(
                tokens,
                5,
                line_no,
                "expected right identifier after 'derive'",
            )?;
            let as_token = tokens.get(6).ok_or_else(|| {
                ParseError::new(
                    line_no,
                    derive_token.column,
                    "expected 'as' after right identifier",
                )
            })?;
            if word(as_token, line_no)? != "as" {
                return Err(ParseError::new(
                    line_no,
                    as_token.column,
                    "expected 'as' after right identifier",
                ));
            }
            let ty_token = tokens.get(7).ok_or_else(|| {
                ParseError::new(line_no, as_token.column, "missing type after 'as'")
            })?;
            let ty = parse_type(ty_token, line_no)?;
            ensure_end(tokens, 8, line_no)?;
            Ok(Stmt::Derive {
                id,
                left: left.clone(),
                right,
                ty,
            })
        }
        other => Err(ParseError::new(
            line_no,
            next.column,
            format!(
                "expected 'node' or identifier after '=' but found '{}'",
                other.as_text()
            ),
        )),
    }
}

fn parse_attest(tokens: &[Token], line_no: usize) -> Result<Stmt, ParseError> {
    let id = expect_word(tokens, 1, line_no, "expected identifier after 'attest'")?;
    let with_token = tokens.get(2).ok_or_else(|| {
        ParseError::new(
            line_no,
            tokens[1].column + 1,
            "expected 'with' after identifier",
        )
    })?;
    if word(with_token, line_no)? != "with" {
        return Err(ParseError::new(
            line_no,
            with_token.column,
            "expected 'with' after identifier",
        ));
    }
    let witness_count_token = tokens.get(3).ok_or_else(|| {
        ParseError::new(
            line_no,
            with_token.column,
            "missing witness count after 'with'",
        )
    })?;
    let witness_count = match &witness_count_token.kind {
        TokenKind::Int(value) if *value >= 0 => *value as usize,
        TokenKind::Int(_) => {
            return Err(ParseError::new(
                line_no,
                witness_count_token.column,
                "witness count must be non-negative",
            ))
        }
        _ => {
            return Err(ParseError::new(
                line_no,
                witness_count_token.column,
                "expected integer witness count",
            ))
        }
    };
    let external_token = tokens.get(4).ok_or_else(|| {
        ParseError::new(
            line_no,
            witness_count_token.column,
            "expected 'external' after witness count",
        )
    })?;
    if word(external_token, line_no)? != "external" {
        return Err(ParseError::new(
            line_no,
            external_token.column,
            "expected 'external' after witness count",
        ));
    }
    let bool_token = tokens.get(5).ok_or_else(|| {
        ParseError::new(
            line_no,
            external_token.column,
            "missing bool after 'external'",
        )
    })?;
    let external = parse_bool(bool_token, line_no)?;
    ensure_end(tokens, 6, line_no)?;
    Ok(Stmt::Attest {
        id,
        witness_count,
        external,
    })
}

fn parse_assert(tokens: &[Token], line_no: usize) -> Result<Stmt, ParseError> {
    let id = expect_word(tokens, 1, line_no, "expected identifier after 'assert'")?;
    let gte_token = tokens.get(2).ok_or_else(|| {
        ParseError::new(
            line_no,
            tokens[1].column + 1,
            "expected '>=' after identifier",
        )
    })?;
    if !matches!(gte_token.kind, TokenKind::Gte) {
        return Err(ParseError::new(
            line_no,
            gte_token.column,
            "expected '>=' after identifier",
        ));
    }
    let strength_token = tokens
        .get(3)
        .ok_or_else(|| ParseError::new(line_no, gte_token.column, "missing strength after '>='"))?;
    let min = parse_strength(strength_token, line_no)?;
    ensure_end(tokens, 4, line_no)?;
    Ok(Stmt::Assert { id, min })
}

fn parse_act(tokens: &[Token], line_no: usize) -> Result<Stmt, ParseError> {
    let id = expect_word(tokens, 1, line_no, "expected identifier after 'act'")?;
    expect_eq(tokens, 2, line_no, "expected '=' after identifier")?;
    let action_token = tokens.get(3).ok_or_else(|| {
        ParseError::new(line_no, tokens[2].column + 1, "missing action after '='")
    })?;
    let action = parse_action(action_token, line_no)?;

    let requires_token = tokens.get(4).ok_or_else(|| {
        ParseError::new(
            line_no,
            action_token.column,
            "expected 'requires' after action",
        )
    })?;
    if word(requires_token, line_no)?.to_ascii_lowercase() != "requires" {
        return Err(ParseError::new(
            line_no,
            requires_token.column,
            "expected 'requires' after action",
        ));
    }

    let strength_token = tokens.get(5).ok_or_else(|| {
        ParseError::new(
            line_no,
            requires_token.column,
            "missing strength after 'requires'",
        )
    })?;
    let requires = parse_strength(strength_token, line_no)?;
    ensure_end(tokens, 6, line_no)?;

    Ok(Stmt::Act {
        id,
        action,
        requires,
    })
}

fn parse_import_path(token: &Token, line_no: usize) -> Result<String, ParseError> {
    let path = word(token, line_no)?;
    let valid = !path.is_empty()
        && path.split('.').all(|segment| !segment.is_empty())
        && !path.contains('/')
        && !path.contains('\\');

    if valid {
        Ok(path)
    } else {
        Err(ParseError::new(
            line_no,
            token.column,
            "invalid import path",
        ))
    }
}

fn parse_expr(token: &Token) -> Result<Expr, ParseError> {
    Ok(match &token.kind {
        TokenKind::Int(value) => Expr::IntLit(*value),
        TokenKind::Str(value) => Expr::StrLit(value.clone()),
        TokenKind::Word(value) => Expr::Ident(value.clone()),
        other => {
            return Err(ParseError::new(
                0,
                token.column,
                format!("unexpected token '{}' in value expression", other.as_text()),
            ))
        }
    })
}

fn parse_action(token: &Token, line_no: usize) -> Result<Action, ParseError> {
    let value = word(token, line_no)?.to_ascii_lowercase();
    match value.as_str() {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        "escalate" => Ok(Action::Escalate),
        other => Err(ParseError::new(
            line_no,
            token.column,
            format!("unknown action '{other}'"),
        )),
    }
}

fn parse_type(token: &Token, line_no: usize) -> Result<Type, ParseError> {
    let value = word(token, line_no)?.to_ascii_lowercase();
    match value.as_str() {
        "i64" => Ok(Type::I64),
        "string" => Ok(Type::String),
        other => Err(ParseError::new(
            line_no,
            token.column,
            format!("unknown type '{other}'"),
        )),
    }
}

fn parse_strength(token: &Token, line_no: usize) -> Result<EvidenceStrength, ParseError> {
    let value = word(token, line_no)?.to_ascii_lowercase();
    match value.as_str() {
        "unverifiable" => Ok(EvidenceStrength::Unverifiable),
        "local" => Ok(EvidenceStrength::Local),
        "witnessed" => Ok(EvidenceStrength::Witnessed),
        "signed" => Ok(EvidenceStrength::Signed),
        "anchored" => Ok(EvidenceStrength::Anchored),
        other => Err(ParseError::new(
            line_no,
            token.column,
            format!("unknown strength '{other}'"),
        )),
    }
}

fn parse_bool(token: &Token, line_no: usize) -> Result<bool, ParseError> {
    let value = word(token, line_no)?.to_ascii_lowercase();
    match value.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(ParseError::new(
            line_no,
            token.column,
            format!("expected bool literal, found '{other}'"),
        )),
    }
}

fn word(token: &Token, line_no: usize) -> Result<String, ParseError> {
    match &token.kind {
        TokenKind::Word(value) => Ok(value.clone()),
        other => Err(ParseError::new(
            line_no,
            token.column,
            format!(
                "expected identifier or keyword, found '{}'",
                other.as_text()
            ),
        )),
    }
}

fn expect_word(
    tokens: &[Token],
    idx: usize,
    line_no: usize,
    message: &str,
) -> Result<String, ParseError> {
    let token = tokens
        .get(idx)
        .ok_or_else(|| ParseError::new(line_no, idx + 1, message))?;
    word(token, line_no)
}

fn expect_eq(
    tokens: &[Token],
    idx: usize,
    line_no: usize,
    message: &str,
) -> Result<(), ParseError> {
    let token = tokens
        .get(idx)
        .ok_or_else(|| ParseError::new(line_no, idx + 1, message))?;
    if matches!(token.kind, TokenKind::Eq) {
        Ok(())
    } else {
        Err(ParseError::new(line_no, token.column, message))
    }
}

fn ensure_end(tokens: &[Token], idx: usize, line_no: usize) -> Result<(), ParseError> {
    if let Some(token) = tokens.get(idx) {
        Err(ParseError::new(
            line_no,
            token.column,
            format!("unexpected token '{}'", token.kind.as_text()),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::nex::ast::{Action, Expr, Stmt, Type};
    use crate::quality::EvidenceStrength;

    #[test]
    fn parses_node_construct() {
        let program = parse("let sum = node 42 signed").expect("parse");
        assert_eq!(program.statements.len(), 1);
        assert!(matches!(
            program.statements[0],
            Stmt::Node {
                id: ref name,
                value: Expr::IntLit(42),
                strength: EvidenceStrength::Signed,
            } if name == "sum"
        ));
    }

    #[test]
    fn parses_string_node_construct() {
        let program = parse("let label = node \"hello\" anchored").expect("parse");
        assert!(matches!(
            program.statements[0],
            Stmt::Node {
                value: Expr::StrLit(ref value),
                strength: EvidenceStrength::Anchored,
                ..
            } if value == "hello"
        ));
    }

    #[test]
    fn parses_attest_construct() {
        let program = parse("attest sum with 2 external true").expect("parse");
        assert!(matches!(
            program.statements[0],
            Stmt::Attest {
                id: ref name,
                witness_count: 2,
                external: true,
            } if name == "sum"
        ));
    }

    #[test]
    fn parses_derive_construct() {
        let program = parse("let total = left derive right as i64").expect("parse");
        assert!(matches!(
            program.statements[0],
            Stmt::Derive {
                id: ref name,
                ref left,
                ref right,
                ty: Type::I64,
            } if name == "total" && left == "left" && right == "right"
        ));
    }

    #[test]
    fn parses_assert_construct() {
        let program = parse("assert total >= anchored").expect("parse");
        assert!(matches!(
            program.statements[0],
            Stmt::Assert {
                id: ref name,
                min: EvidenceStrength::Anchored,
            } if name == "total"
        ));
    }

    #[test]
    fn parses_act_construct() {
        let program = parse("act decision = deny requires signed").expect("parse");
        assert!(matches!(
            program.statements[0],
            Stmt::Act {
                id: ref name,
                action: Action::Deny,
                requires: EvidenceStrength::Signed,
            } if name == "decision"
        ));
    }

    #[test]
    fn parses_comment_construct() {
        let program = parse("  # comment only").expect("parse");
        assert!(program.statements.is_empty());
    }

    #[test]
    fn parses_use_construct() {
        let program = parse("use lib.risk").expect("parse");
        assert!(matches!(
            program.statements[0],
            Stmt::Use { ref path } if path == "lib.risk"
        ));
    }

    #[test]
    fn unknown_keyword_errors() {
        let err = parse("bogus total").expect_err("parse should fail");
        assert!(err.to_string().contains("unknown keyword"));
    }

    #[test]
    fn missing_strength_errors() {
        let err = parse("let sum = node 1").expect_err("missing strength");
        assert!(err.to_string().contains("missing strength"));
    }

    #[test]
    fn missing_external_keyword_after_with_errors() {
        let err = parse("attest sum with 2 true").expect_err("missing external keyword");
        assert!(err
            .to_string()
            .contains("expected 'external' after witness count"));
    }

    #[test]
    fn missing_requires_keyword_after_act_errors() {
        let err = parse("act decision = deny signed").expect_err("missing requires keyword");
        assert!(err.to_string().contains("expected 'requires' after action"));
    }
}
