// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
mod cursor;
mod error;
mod grouping_extension;
mod infix_extension;
mod keyword_extension;
mod lexer;
mod operation;
mod postfix_extension;
mod prefix_extension;
mod statement;
mod token;
mod variable_extension;

pub use error::{ErrorKind, SyntaxError};
pub use lexer::Lexer;
pub use statement::*;
pub use storage::nvt::ACT;
pub use token::Base as NumberBase;
pub use token::Category as TokenCategory;
pub use token::IdentifierType;
pub use token::Token;
pub use token::Tokenizer;

/// Parses given code and returns found Statements and Errors
///
/// # Examples
/// Basic usage:
///
/// ```
/// use nasl_syntax::{Statement, SyntaxError};
/// let statements =
///     nasl_syntax::parse("a = 23;b = 1;").collect::<Vec<Result<Statement, SyntaxError>>>();
/// ````
pub fn parse(code: &str) -> impl Iterator<Item = Result<Statement, SyntaxError>> + '_ {
    let tokenizer = Tokenizer::new(code);
    Lexer::new(tokenizer)
}

#[cfg(test)]
mod tests {
    use crate::{
        cursor::Cursor,
        token::{Category, IdentifierType, Token, Tokenizer},
        AssignOrder, Statement, SyntaxError,
    };

    #[test]
    fn use_cursor() {
        let mut cursor = Cursor::new("  \n\tdisplay(12);");
        cursor.skip_while(|c| c.is_whitespace());
        assert_eq!(cursor.advance(), Some('d'));
    }

    #[test]
    fn use_tokenizer() {
        let tokenizer = Tokenizer::new("local_var hello = 'World!';");
        let all_tokens = tokenizer.collect::<Vec<Token>>();
        assert_eq!(
            all_tokens,
            vec![
                Token {
                    category: Category::Identifier(IdentifierType::LocalVar),
                    position: (1, 1)
                },
                Token {
                    category: Category::Identifier(IdentifierType::Undefined("hello".to_owned())),
                    position: (1, 11)
                },
                Token {
                    category: Category::Equal,
                    position: (1, 17)
                },
                Token {
                    category: Category::Data("World!".as_bytes().to_vec()),
                    position: (1, 19)
                },
                Token {
                    category: Category::Semicolon,
                    position: (1, 27)
                }
            ]
        );
    }

    #[test]
    fn use_parser() {
        use Category::*;
        use Statement::*;
        let statements =
            super::parse("a = 23;b = 1;").collect::<Vec<Result<Statement, SyntaxError>>>();
        assert_eq!(
            statements,
            vec![
                Ok(Assign(
                    Equal,
                    AssignOrder::AssignReturn,
                    Box::new(Variable(Token {
                        category: Identifier(IdentifierType::Undefined("a".to_owned())),
                        position: (1, 1)
                    },)),
                    Box::new(Primitive(Token {
                        category: Number(23),
                        position: (1, 5)
                    }))
                )),
                Ok(Assign(
                    Equal,
                    AssignOrder::AssignReturn,
                    Box::new(Variable(Token {
                        category: Identifier(IdentifierType::Undefined("b".to_owned())),
                        position: (1, 8)
                    },)),
                    Box::new(Primitive(Token {
                        category: Number(1),
                        position: (1, 12)
                    }))
                ))
            ]
        );
    }
}
