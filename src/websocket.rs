use nom::combinator::cond;
use nom::error::{ContextError, Error as NomError, ErrorKind as NomErrorKind};
use nom::{
    bits::bits, bits::complete::take as take_bits, combinator::map,
    error::ParseError as NomParseError, number::complete::be_u32, sequence::tuple,
};
use pretty_hex::*;

use crate::Error;

#[derive(Debug)]
pub enum ErrorKind {
    Nom(NomErrorKind),
    Context(&'static str),
}

#[derive(Debug)]
pub struct ParseError<I> {
    pub errors: Vec<(I, ErrorKind)>,
}

impl<I> NomParseError<I> for ParseError<I> {
    fn from_error_kind(input: I, kind: NomErrorKind) -> Self {
        let errors = vec![(input, ErrorKind::Nom(kind))];
        Self { errors }
    }

    fn append(input: I, kind: NomErrorKind, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Nom(kind)));
        other
    }
}

impl<I> ContextError<I> for ParseError<I> {
    fn add_context(input: I, ctx: &'static str, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Context(ctx)));
        other
    }
}

pub type Input<'a> = &'a [u8];
pub type Result<'a, T> = nom::IResult<Input<'a>, T, ParseError<Input<'a>>>;

#[derive(Debug)]
pub struct Frame {
    pub fin: u8,
    pub rsv: u8,
    pub mask: u8,
    pub opcode: u8,
    pub length: u8,
    pub masking_key: u32,
}

impl<I> nom::ErrorConvert<ParseError<I>> for NomError<I> {
    fn convert(self) -> ParseError<I> {
        let errors = vec![(self.input, ErrorKind::Nom(self.code))];
        ParseError { errors }
    }
}

impl<I> nom::ErrorConvert<ParseError<I>> for NomError<(I, usize)> {
    fn convert(self) -> ParseError<I> {
        let errors = vec![(self.input.0, ErrorKind::Nom(self.code))];
        ParseError { errors }
    }
}

impl<I> From<nom::Err<ParseError<I>>> for Error {
    fn from(e: nom::Err<ParseError<I>>) -> Self {
        match e {
            nom::Err::Error(_e) => Error::ParseError("nom parser errors go here.".into()),
            nom::Err::Incomplete(_) => Error::ParseError("Not enough data.".into()),
            nom::Err::Failure(_) => Error::ParseError("Critical parser error.".into()),
        }
    }
}

impl Frame {
    pub fn parse_masking_key(input: &[u8]) -> Result<u32> {
        be_u32(input)
    }

    pub fn parse_pre_payload(input: &[u8]) -> Result<(u8, u8, u8, u8, u8)> {
        bits::<_, _, NomError<(&[u8], usize)>, _, _>(tuple((
            take_bits(1usize),
            take_bits(3usize),
            take_bits(4usize),
            take_bits(1usize),
            take_bits(7usize),
        )))(input)
    }

    pub fn from_bytes(input: Vec<u8>) -> std::result::Result<(Vec<u8>, Frame), Error> {
        println!("input: {}", input.hex_dump());
        let (rest, parsed) = Self::parse_pre_payload(&input)?;
        let (fin, rsv, opcode, mask, payload_hint) = parsed;
        let payload_word_len = match payload_hint {
            126 => 16,
            127 => 64,
            _ => payload_hint,
        };
        let payload_len = cond(payload_word_len >= 16, take_bits(payload_word_len));

        let (payload, frame) = map(
            tuple((
                bits::<_, _, NomError<(&[u8], usize)>, _, _>(payload_len),
                Self::parse_masking_key,
            )),
            move |(payload_len, masking_key)| Self {
                fin,
                rsv,
                mask,
                opcode,
                length: payload_len.unwrap_or(payload_word_len),
                masking_key,
            },
        )(rest)?;

        Ok((payload.to_owned(), frame))
    }
}
